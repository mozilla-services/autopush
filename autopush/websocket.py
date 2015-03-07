import json
import uuid
import time

import cyclone.web
from autobahn.twisted.websocket import WebSocketServerProtocol
from twisted.internet.threads import deferToThread
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredList
from twisted.python import log


def more_time():
    return int(time.time() * 1000)


class SimplePushServerProtocol(WebSocketServerProtocol):
    def onConnect(self, request):
        self.uaid = None
        self.last_ping = 0
        self.accept_notification = True
        self.check_storage = False
        self.connected_at = more_time()

        self._check_notifications = False

        # Hanger for common actions we defer
        self._notification_fetch = None
        self._hello = None
        self._register = None

        # Reflects updates sent that haven't been ack'd
        self.updates_sent = {}
        self.channels = set()

    #############################################################
    #                    Connection Methods
    #############################################################
    def onMessage(self, payload, isBinary):
        if isBinary:
            print("Binary message received: {0} bytes".format(len(payload)))
            return

        try:
            data = json.loads(payload.decode('utf8'))
        except:
            self.sendClose()
            return

        # We're registering the user, any other action is not allowed
        # Cancel the registration and drop them
        if self._hello:
            self._hello.cancel()
            self.sendClose()
            return

        # A registration call can't occur two at a time
        if self._register:
            self._register.cancel()
            self.sendClose()

        # Without a UAID, hello must be next
        if not self.uaid:
            return self.process_hello(data)

        # Ping's get a ping reply
        if data == {}:
            return self.process_ping()

        # Message needs a type
        if "messageType" not in data:
            self.sendClose()

        cmd = data["messageType"]
        if cmd == "register":
            return self.process_register(data)
        elif cmd == "unregister":
            return self.process_unregister(data)
        elif cmd == "ack":
            return self.process_ack(data)
        else:
            self.sendClose()

    def onClose(self, wasClean, code, reason):
        uaid = getattr(self, "uaid", None)
        if uaid:
            self.cleanUp()

    def cleanUp(self):
        if self.uaid and self.settings.clients.get(self.uaid) == self:
            del self.settings.clients[self.uaid]

    #############################################################
    #                Message Processing Methods
    #############################################################
    def process_hello(self, data):
        # This must be a helo, or we kick the client
        cmd = data.get("messageType")
        if cmd != "hello":
            self.sendClose()
            return

        uaid = data.get("uaid")
        valid = False
        if uaid:
            try:
                valid = bool(uuid.UUID(uaid))
            except ValueError:
                pass
        if not uaid or not valid:
            uaid = str(uuid.uuid4())

        self.uaid = uaid

        # User exists?
        router = self.settings.router
        url = "http://%s:%s/push" % (self.settings.hostname,
                                     self.settings.router_port)

        # Attempt to register the user for this session
        d = deferToThread(router.register_user, uaid, url, self.connected_at)
        d.addCallback(self.finish_hello)
        d.addErrback(self.err_hello)
        self._register = d
        return d

    def err_hello(self, failure):
        msg = {"messageType": "hello", "reason": "error", "status": 500}
        self.sendMessage(json.dumps(msg).encode('utf8'), False)
        self.sendClose()

    def finish_hello(self, result):
        self._register = None
        if not result:
            # Registration failed
            msg = {"messageType": "hello", "reason": "already_connected",
                   "status": 500}
            self.sendMessage(json.dumps(msg).encode('utf8'), False)
            return

        msg = {"messageType": "hello", "uaid": self.uaid, "status": 200}
        self.settings.clients[self.uaid] = self
        self.sendMessage(json.dumps(msg).encode('utf8'), False)
        self.process_notifications()

    def process_notifications(self):
        # Are we already running?
        if self._notification_fetch:
            return

        # Prevent notification acceptance while we check storage
        self.accept_notification = False
        self._check_notifications = False

        # Prevent repeat calls
        d = deferToThread(self.settings.storage.fetch_notifications, self.uaid)
        d.addBoth(self.finish_notifications)
        self._notification_fetch = d

    def error_notifications(self, fail):
        # Ignore errors, re-run if we should
        self.accept_notification = True
        self._notification_fetch = None
        if self._check_notifications:
            self._check_notifications = False
            reactor.callLater(1, self.process_notifications)

    def finish_notifications(self, notifs):
        # We want to allow notifications again
        self.accept_notification = True
        self._notification_fetch = None

        updates = []
        # Track outgoing, screen out things we've seen
        for s in notifs:
            chid = s.get('chid')
            version = int(s.get('version'))
            if self.updates_sent.get(chid, 0) >= version:
                continue
            self.updates_sent[chid] = version
            updates.append({"channelID": chid, "version": version})
        if updates:
            msg = json.dumps({"messageType": "notification",
                              "updates": updates})
            self.sendMessage(msg.encode('utf8'), False)

        # Were we told to check notifications again?
        if self._check_notifications:
            self._check_notifications = False
            reactor.callLater(1, self.process_notifications)

    def process_ping(self):
        now = time.time()
        if now - self.last_ping < self.settings.min_ping_interval:
            return self.sendClose()
        self.last_ping = now
        return self.sendMessage("{}", False)

    @inlineCallbacks
    def process_register(self, data):
        if "channelID" not in data:
            returnValue(self.bad_message("register"))
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            returnValue(self.bad_message("register"))

        token = yield deferToThread(
            self.settings.fernet.encrypt,
            (self.uaid + ":" + chid).encode('utf8'))
        host = self.settings.hostname
        port = self.settings.endpoint_port
        msg = {"messageType": "register",
               "channelID": chid,
               "pushEndpoint": "http://%s:%s/push/%s" % (host, port, token),
               "status": 200
               }
        # TODO: Someone could abuse registration and not receive to make
        #       us buffer lots and lots of data
        self.sendMessage(json.dumps(msg).encode('utf8'), False)

    def process_unregister(self, data):
        if "channelID" not in data:
            return self.bad_message("unregister")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("unregister")

        # Delete any record from storage, we don't wait for this
        d = deferToThread(self.settings.storage.delete_notification,
                          self.uaid, chid)
        d.addErrback(log.err)
        data["status"] = 200
        self.sendMessage(json.dumps(data).encode("utf8"), False)

    def process_ack(self, data):
        updates = data.get("updates")
        if not updates or not isinstance(updates, list):
            return self.bad_message("ack")

        defers = []
        for update in updates:
            chid = update.get("channelID")
            version = update.get("version")
            if not chid or not version:
                continue

            if chid in self.updates_sent and \
               self.updates_sent[chid] == version:
                del self.updates_sent[chid]
            else:
                # An ack for something we aren't tracking?
                continue

            # Attempt to delete this notification from storage
            storage = self.settings.storage

            # TODO: Check result here, and do something if this delete fails
            # like maybe do a new storage check
            d = deferToThread(storage.delete_notification,
                              self.uaid, chid, version)
            d.addErrback(log.err)
            defers.append(d)
        if defers:
            dl = DeferredList(defers)
            dl.addBoth(self.check_missed_notifications)

    def check_missed_notifications(self, results):
        # If they're all ack'd, we will send notifications again
        if not self.updates_sent:
            self.accept_notification = True

            # See if we are already checking for notifications, cancel that
            # and start again
            if self._notification_fetch:
                self._notification_fetch.cancel()
                self._notification_fetch = None
                self._check_notifications = True

            # Should we check again?
            if self._check_notifications:
                self.process_notifications()

    def bad_message(self, typ):
        msg = {"messageType": typ, "status": 401}
        self.sendMessage(json.dumps(msg).encode('utf8'), False)

    ####################################
    # Utility function for external use
    def send_notifications(self, updates):
        toSend = []
        for update in updates:
            channel_id, version = update["channelID"], update["version"]
            if channel_id in self.updates_sent and \
               self.updates_sent[channel_id] > version:
                # Already sent a newer version for this channel, so don't
                # update our versioning
                continue
            # Otherwise we can record we sent this version
            self.updates_sent[channel_id] = version
            toSend.append(update)
        msg = {"messageType": "notification", "updates": toSend}
        self.sendMessage(json.dumps(msg).encode('utf8'), False)
        self.accept_notification = False


class RouterHandler(cyclone.web.RequestHandler):
    def put(self, uaid):
        client = self.settings.clients.get(uaid)
        if not client:
            self.set_status(404)
            return self.write("Client not connected.")

        if not client.accept_notification:
            # Let the client know to check notifications again
            client._check_notifications = True
            self.set_status(503)
            return self.write("Client busy.")

        updates = json.loads(self.request.body)
        client.send_notifications(updates)
        return self.write("Client accepted for delivery")
