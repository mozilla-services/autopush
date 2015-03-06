import json
import uuid
import time

import cyclone.web
from autobahn.twisted.websocket import WebSocketServerProtocol
from twisted.internet.threads import deferToThread
from twisted.internet.defer import inlineCallbacks, returnValue


def more_time():
    return int(time.time() * 1000)


class SimplePushServerProtocol(WebSocketServerProtocol):
    def onConnect(self, request):
        self.uaid = None
        self.last_ping = 0
        self.accept_notification = True
        self.check_storage = False
        self.connected_at = more_time()

        # Reflects updates sent that haven't been ack'd
        self.updates_sent = {}

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

        # If this was real, we'd handle un-ack'd notifications here
        print("WebSocket connection closed: {0}".format(reason))

    def cleanUp(self):
        if self.uaid and self.settings.clients.get(self.uaid) == self:
            del self.settings.clients[self.uaid]

    #############################################################
    #                Message Processing Methods
    #############################################################
    @inlineCallbacks
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
        result = yield router.register_user(uaid, url, self.connected_at)

        if not result:
            # Registration failed
            msg = {"messageType": "hello", "reason": "already_connected",
                   "status": 500}
            self.sendMessage(json.dumps(msg).encode('utf8'), False)
            returnValue(None)

        msg = {"messageType": "hello", "uaid": uaid, "status": 200}
        self.settings.clients[self.uaid] = self
        self.sendMessage(json.dumps(msg).encode('utf8'), False)
        self.process_notifications()

    @inlineCallbacks
    def process_notifications(self):
        # Prevent notification acceptance while we check storage
        self.accept_notification = False

        notifs = yield self.settings.storage.fetch_notifications(self.uaid)
        if not notifs:
            # Nothing to deliver, we're ok for notifications
            self.accept_notification = True
            returnValue(None)

        updates = [{"channelID": s.get("chid"),
                    "version": int(s.get("version"))}
                   for s in notifs]
        msg = json.dumps({"messageType": "notification", "updates": updates})
        self.sendMessage(msg.encode('utf8'), False)

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
        data["status"] = 200
        self.sendMessage(json.dumps(data).encode("utf8"), False)

    def process_ack(self, data):
        updates = data.get("updates")
        if not updates or not isinstance(updates, list):
            return self.bad_message("ack")
        for update in updates:
            chid = update.get("channelID")
            version = update.get("version")
            if not chid or not version:
                return self.bad_message("ack")

            if chid in self.updates_sent and \
               self.updates_sent[chid] == version:
                del self.updates_sent[chid]

            # Attempt to delete this notification from storage
            storage = self.settings.storage

            # TODO: Check result here, and do something if this delete fails
            # like maybe do a new storage check
            storage.delete_notification(self.uaid, chid, version)

        # If they're all ack'd, we will send notifications again
        if not self.updates_sent:
            self.accept_notification = True

            # See if we missed any notifications while waiting for acks
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
            self.set_status(503)
            return self.write("Client busy.")

        updates = json.loads(self.request.body)
        client.send_notifications(updates)
        return self.write("Client accepted for delivery")
