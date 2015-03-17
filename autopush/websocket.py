import json
import time
import uuid

import cyclone.web
from autobahn.twisted.websocket import WebSocketServerProtocol
from twisted.internet import reactor
from twisted.internet.defer import (
    DeferredList,
    CancelledError
)
from twisted.internet.threads import deferToThread
from twisted.python import log


def ms_time():
    return int(time.time() * 1000)


def periodic_reporter(settings):
    settings.metrics.gauge("update.client.connections",
                           len(settings.clients))


class SimplePushServerProtocol(WebSocketServerProtocol):
    def onConnect(self, request):
        self.metrics = self.settings.metrics
        self.metrics.increment("client.socket.connect")
        self.uaid = None
        self.last_ping = 0
        self.accept_notification = True
        self.check_storage = False
        self.connected_at = ms_time()

        self._check_notifications = False

        # Hanger for common actions we defer
        self._notification_fetch = None
        self._register = None

        # Reflects updates sent that haven't been ack'd
        self.updates_sent = {}

        # Track notifications we don't need to delete separately
        self.direct_updates = {}
        self.channels = set()

    #############################################################
    #                    Connection Methods
    #############################################################
    def processHandshake(self):
        """Disable host port checking on nonstandard ports since some
        clients are buggy and don't provide it"""
        port = self.settings.port
        hide = port != 80 and port != 443
        if not hide:
            return WebSocketServerProtocol.processHandshake(self)

        old_port = self.factory.externalPort
        try:
            self.factory.externalPort = None
            return WebSocketServerProtocol.processHandshake(self)
        finally:
            self.factory.externalPort = old_port

    def onMessage(self, payload, isBinary):
        if isBinary:
            self.sendClose()
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
        if cmd == "hello":
            return self.process_hello(data)
        elif cmd == "register":
            return self.process_register(data)
        elif cmd == "unregister":
            return self.process_unregister(data)
        elif cmd == "ack":
            return self.process_ack(data)
        else:
            self.sendClose()

    def onClose(self, wasClean, code, reason):
        # TODO: Any notifications directly delivered but not ack'd need
        # to be punted to an endpoint router
        uaid = getattr(self, "uaid", None)
        if uaid:
            self.cleanUp()

    def cleanUp(self):
        self.metrics.increment("client.socket.disconnect")
        elapsed = (ms_time() - self.connected_at) / 1000.0
        self.metrics.timing("client.socket.lifespan", duration=elapsed)
        if self.uaid and self.settings.clients.get(self.uaid) == self:
            del self.settings.clients[self.uaid]
            for defer in [self._notification_fetch, self._register]:
                if defer:
                    defer.cancel()

    def sendJSON(self, body):
        self.sendMessage(json.dumps(body).encode('utf8'), False)

    #############################################################
    #                Message Processing Methods
    #############################################################
    def process_hello(self, data):
        # This must be a helo, or we kick the client
        cmd = data.get("messageType")
        if cmd != "hello":
            self.sendClose()
            return

        if self.uaid:
            self.sendJSON(
                {"messageType": "hello", "reason": "duplicate hello",
                 "status": 401})
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
        url = "http://%s:%s" % (self.settings.router_hostname,
                                self.settings.router_port)

        # Attempt to register the user for this session
        self.transport.pauseProducing()
        d = deferToThread(router.register_user, uaid, url, self.connected_at)
        d.addCallback(self.finish_hello)
        d.addErrback(self.err_hello)
        self._register = d
        return d

    def err_hello(self, failure):
        self.transport.resumeProducing()
        msg = {"messageType": "hello", "reason": "error", "status": 503}
        self.sendJSON(msg)
        self.sendClose()

    def finish_hello(self, result):
        self.transport.resumeProducing()
        self._register = None
        if not result:
            # Registration failed
            msg = {"messageType": "hello", "reason": "already_connected",
                   "status": 500}
            self.sendMessage(json.dumps(msg).encode('utf8'), False)
            return

        msg = {"messageType": "hello", "uaid": self.uaid, "status": 200}
        self.settings.clients[self.uaid] = self
        self.sendJSON(msg)
        self.metrics.increment("updates.client.hello")
        self.process_notifications()

    def process_notifications(self):
        # Are we already running?
        if self._notification_fetch:
            # Cancel the prior, last one wins
            self._notification_fetch.cancel()

        self._check_notifications = False

        # Prevent repeat calls
        d = deferToThread(self.settings.storage.fetch_notifications, self.uaid)
        d.addErrback(self.cancel_notifications)
        d.addErrback(self.error_notifications)
        d.addCallback(self.finish_notifications)
        self._notification_fetch = d

    def cancel_notifications(self, fail):
        # Don't do anything else, we got cancelled
        fail.trap(CancelledError)

    def error_notifications(self, fail):
        # Ignore errors, re-run if we should
        self._notification_fetch = None
        if self._check_notifications:
            self._check_notifications = False
            reactor.callLater(1, self.process_notifications)

    def finish_notifications(self, notifs):
        self._notification_fetch = None

        updates = []
        notifs = notifs or []
        # Track outgoing, screen out things we've seen that weren't
        # ack'd yet
        for s in notifs:
            chid = s['chid']
            version = int(s['version'])
            if self.updates_sent.get(chid, 0) >= version:
                continue
            self.updates_sent[chid] = version
            updates.append({"channelID": chid, "version": version})
        if updates:
            # If we need to send notifications, we now expect a response
            # before any more notification processing
            self.accept_notification = False
            msg = {"messageType": "notification", "updates": updates}
            self.sendJSON(msg)

        # Were we told to check notifications again?
        if self._check_notifications:
            self._check_notifications = False
            reactor.callLater(1, self.process_notifications)

    def process_ping(self):
        now = time.time()
        if now - self.last_ping < self.settings.min_ping_interval:
            self.metrics.increment("updates.client.too_many_pings")
            return self.sendClose()
        self.last_ping = now
        self.metrics.increment("updates.client.ping")
        return self.sendMessage("{}", False)

    def process_register(self, data):
        if "channelID" not in data:
            return self.bad_message("register")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("register")

        self.transport.pauseProducing()

        d = deferToThread(
            self.settings.fernet.encrypt,
            (self.uaid + ":" + chid).encode('utf8'))
        d.addCallbacks(self.finish_register, self.error_register,
                       callbackArgs=(chid,))

    def error_register(self, fail):
        self.transport.resumeProducing()
        msg = {"messageType": "register", "status": 500}
        self.sendJSON(msg)

    def finish_register(self, token, chid):
        self.transport.resumeProducing()
        url = self.settings.endpoint_url
        msg = {"messageType": "register",
               "channelID": chid,
               "pushEndpoint": "%s/push/%s" % (url, token),
               "status": 200
               }
        self.sendJSON(msg)
        self.metrics.increment("updates.client.register")

    def process_unregister(self, data):
        if "channelID" not in data:
            return self.bad_message("unregister")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("unregister")

        self.metrics.increment("updates.client.unregister")

        # Delete any record from storage, we don't wait for this
        d = deferToThread(self.settings.storage.delete_notification,
                          self.uaid, chid)
        d.addErrback(self.force_delete, chid)
        data["status"] = 200
        self.sendJSON(data)

    def force_delete(self, failure, chid):
        """Forces another delete call through until it works"""
        d = deferToThread(self.settings.storage.delete_notification,
                          self.uaid, chid)
        d.addErrback(self.force_delete, chid)

    def process_ack(self, data):
        updates = data.get("updates")
        if not updates or not isinstance(updates, list):
            return self.bad_message("ack")

        self.metrics.increment("updates.client.ack")
        defers = []
        for update in updates:
            chid = update.get("channelID")
            version = update.get("version")
            if not chid or not version:
                continue

            skip = False
            # We always need to delete direct updates
            if self.direct_updates.get(chid) == version:
                del self.direct_updates[chid]
                skip = True

            # If this is the same as a version we sent, delete
            # as well
            if self.updates_sent.get(chid) == version:
                del self.updates_sent[chid]
            else:
                # An ack for something we aren't tracking?
                continue

            if skip:
                continue

            # Attempt to delete this notification from storage
            storage = self.settings.storage

            # TODO: Check result here, and do something if this delete fails
            # like maybe do a new storage check
            d = deferToThread(storage.delete_notification,
                              self.uaid, chid, version)
            d.addCallback(self.check_ack, self.uaid, chid, version)
            d.addErrback(log.err)
            defers.append(d)

        # If that was the last ack we were expecting, we're clear now
        if not self.updates_sent:
            self.accept_notification = True

        if defers:
            self.transport.pauseProducing()
            dl = DeferredList(defers)
            dl.addBoth(self.check_missed_notifications)

    def check_ack(self, result, uaid, chid, version):
        if result:
            return None

        # Retry the operation and return its new deferred
        d = deferToThread(self.settings.storage.delete_notification, uaid,
                          chid, version)
        d.addCallback(self.check_ack, uaid, chid, version)
        d.addErrback(log.err)
        return d

    def check_missed_notifications(self, results):
        # Check that they all ack's succeeded against storage
        defers = []
        for success, value in results:
            if not success:
                # Skip unknown errors
                continue
            if value:
                defers.append(value)

        # Any failures to retry?
        if defers:
            dl = DeferredList(defers)
            dl.addBoth(self.check_missed_notifications)
            return

        # Resume consuming ack's
        self.transport.resumeProducing()

        # If they're all ack'd, we will send notifications again
        if not self.updates_sent:
            self.accept_notification = True

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
            self.direct_updates[channel_id] = version
            self.updates_sent[channel_id] = version
            toSend.append(update)
        msg = {"messageType": "notification", "updates": toSend}
        self.sendJSON(msg)
        self.accept_notification = False


class RouterHandler(cyclone.web.RequestHandler):
    def put(self, uaid):
        settings = self.settings
        client = settings.clients.get(uaid)
        if not client:
            self.set_status(404)
            settings.metrics.increment("updates.router.disconnected")
            return self.write("Client not connected.")

        if not client.accept_notification:
            self.set_status(503)
            settings.metrics.increment("updates.router.busy")
            return self.write("Client busy.")

        updates = json.loads(self.request.body)
        client.send_notifications(updates)
        settings.metrics.increment("updates.router.received")
        return self.write("Client accepted for delivery")


class NotificationHandler(cyclone.web.RequestHandler):
    def put(self, uaid):
        client = self.settings.clients.get(uaid)
        settings = self.settings
        if not client:
            self.set_status(404)
            settings.metrics.increment("updates.notification.disconnected")
            return self.write("Client not connected.")

        if not client.accept_notification:
            # Client already busy waiting for stuff, flag for check
            self._check_notifications = True
            self.set_status(202)
            settings.metrics.increment("updates.notification.flagged")
            return self.write("Flagged for Notification check")

        # Client is online and idle, start a notification check
        client.process_notifications()
        settings.metrics.increment("updates.notification.checking")
        self.set_status(200)
        self.write("Notification check started")
