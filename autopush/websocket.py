import json
import time
import uuid
from functools import wraps

import cyclone.web
from autobahn.twisted.websocket import WebSocketServerProtocol
from twisted.internet import reactor
from twisted.internet.defer import (
    Deferred,
    DeferredList,
    CancelledError
)
from twisted.internet.error import (
    ConnectError, ConnectionRefusedError, UserError
)
from twisted.internet.interfaces import IProducer
from twisted.internet.threads import deferToThread
from twisted.python import failure, log
from zope.interface import implements

from autopush.protocol import IgnoreBody
from autopush.utils import validate_uaid


def ms_time():
    return int(time.time() * 1000)


def periodic_reporter(settings):
    settings.metrics.gauge("update.client.writers",
                           len(reactor.getWriters()))
    settings.metrics.gauge("update.client.readers",
                           len(reactor.getReaders()))
    settings.metrics.gauge("update.client.connections",
                           len(settings.clients))
    settings.metrics.gauge("update.client.ws_connections",
                           settings.factory.countConnections)


def log_exception(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception:
            self.log_err(failure.Failure())
            raise
    return wrapper


class SimplePushServerProtocol(WebSocketServerProtocol):
    implements(IProducer)

    # Testing purposes
    parent_class = WebSocketServerProtocol

    # Defer helpers
    def deferToThread(self, func, *args, **kwargs):
        d = deferToThread(func, *args, **kwargs)

        def trapCancel(fail):
            fail.trap(CancelledError)

        self._callbacks.append(d)

        def f(result):
            if d in self._callbacks:
                self._callbacks.remove(d)
            return result
        d.addBoth(f)
        d.addErrback(trapCancel)
        return d

    def deferToLater(self, when, func, *args, **kwargs):
        d = Deferred()

        def trapCancel(fail):
            fail.trap(CancelledError)

        d.addErrback(trapCancel)
        self._callbacks.append(d)

        def f():
            if d in self._callbacks:
                self._callbacks.remove(d)
            try:
                result = func(*args, **kwargs)
                d.callback(result)
            except:
                d.errback(failure.Failure())
        reactor.callLater(when, f)
        return d

    def defer(self):
        d = Deferred()

        def removeDefer(result):
            self._callbacks.remove(d)
            return result

        def trapCancel(fail):
            fail.trap(CancelledError)

        d.addErrback(trapCancel)
        d.addCallback(removeDefer)
        self._callbacks.append(d)
        return d

    @property
    def base_tags(self):
        return self._base_tags if self._base_tags else None

    def log_err(self, failure, **kwargs):
        log.err(failure, **kwargs)

    def pauseProducing(self):
        self._paused = True

    def resumeProducing(self):
        self._paused = False

    def stopProducing(self):
        self._paused = True
        self._should_stop = True

    @property
    def paused(self):
        return self._paused

    @log_exception
    def _connectionLost(self, reason):
        """Make extra sure we log any exceptions in here, this shouldn't be
        needed"""
        return WebSocketServerProtocol._connectionLost(self, reason)

    @log_exception
    def _sendAutoPing(self):
        """Override for sanity checking during auto-ping interval"""
        if not self.uaid:
            # No uaid yet, drop the connection
            self.metrics.increment("client.autoping.no_uaid",
                                   tags=self.base_tags)
            self.sendClose()
        elif self.ap_settings.clients.get(self.uaid) != self:
            # UAID, but we're not in clients anymore for some reason
            self.metrics.increment("client.autoping.invalid_client",
                                   tags=self.base_tags)
            self.sendClose()
        return WebSocketServerProtocol._sendAutoPing(self)

    @log_exception
    def sendClose(self, code=None, reason=None):
        """Override to add tracker that ensures the connection is truly
        torn down"""
        reactor.callLater(5+self.closeHandshakeTimeout, self.nukeConnection)
        return WebSocketServerProtocol.sendClose(self, code, reason)

    @log_exception
    def nukeConnection(self):
        # Did onClose get called? If so, we shutdown properly, no worries.
        if hasattr(self, "_shutdown_ran"):
            return

        # Uh-oh, we have not been shut-down properly, report detailed data
        self.metrics.increment("client.error.sendClose_failed",
                               tags=self.base_tags)
        log.msg("sendClose failed to result in onClose", state=str(self.state))

        self.transport.abortConnection()
        # Add a last callback to verify onClose finally was run
        reactor.callLater(60, self.verifyNuke)

    @log_exception
    def verifyNuke(self):
        if hasattr(self, "_shutdown_ran"):
            return

        # abortConnection still has failed to shut this down one minute later
        self.metrics.increment("client.error.abortConnection_failed",
                               tags=self.base_tags)

    @log_exception
    def onConnect(self, request):
        # Setup ourself to handle producing the data
        self.transport.bufferSize = 2 * 1024
        self.transport.registerProducer(self, True)

        self._callbacks = []

        if request:
            self._user_agent = request.headers.get("user-agent")
        else:
            self._user_agent = None
        self._base_tags = []
        if self._user_agent:
            self._base_tags.append("user-agent:%s" % self._user_agent)
        self._should_stop = False
        self._paused = False
        self.metrics = self.ap_settings.metrics
        self.metrics.increment("client.socket.connect", tags=self.base_tags)
        self.uaid = None
        self.last_ping = 0
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
        self.bridge = None

    #############################################################
    #                    Connection Methods
    #############################################################
    @log_exception
    def processHandshake(self):
        """Disable host port checking on nonstandard ports since some
        clients are buggy and don't provide it"""
        port = self.ap_settings.port
        hide = port != 80 and port != 443
        if not hide:
            return self.parent_class.processHandshake(self)

        old_port = self.factory.externalPort
        try:
            self.factory.externalPort = None
            return self.parent_class.processHandshake(self)
        finally:
            self.factory.externalPort = old_port

    @log_exception
    def onMessage(self, payload, isBinary):
        if isBinary:
            self.sendClose()
            return

        data = None
        try:
            data = json.loads(payload.decode('utf8'))
        except:
            pass

        if not isinstance(data, dict):
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
            return

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

    @log_exception
    def onClose(self, wasClean, code, reason):
        uaid = getattr(self, "uaid", None)
        self._shutdown_ran = True
        self._should_stop = True
        if uaid:
            self.cleanUp()

    def cleanUp(self):
        self.metrics.increment("client.socket.disconnect", tags=self.base_tags)
        elapsed = (ms_time() - self.connected_at) / 1000.0
        self.metrics.timing("client.socket.lifespan", duration=elapsed,
                            tags=self.base_tags)

        # Cleanup our client entry
        if self.uaid and self.ap_settings.clients.get(self.uaid) == self:
            del self.ap_settings.clients[self.uaid]

        # Cancel any outstanding deferreds
        for d in self._callbacks:
            d.cancel()

        # Attempt to deliver any notifications not originating from storage
        if self.direct_updates:
            defers = []
            for chid, version in self.direct_updates.items():
                d = deferToThread(
                    self.ap_settings.storage.save_notification,
                    self.uaid,
                    chid,
                    version
                )
                d.addErrback(self.log_err)
                defers.append(d)

            # Tag on the notifier once everything has been stored
            dl = DeferredList(defers)
            dl.addBoth(self._lookup_node)

        # Delete and remove remaining dicts and lists
        del self.direct_updates
        del self.updates_sent

    def _lookup_node(self, results):
        """Looks up the node to send a notify for it to check storage if
        connected"""
        # Locate the node that has this client connected
        d = deferToThread(
            self.ap_settings.router.get_uaid,
            self.uaid
        )
        d.addCallback(self._notify_node)
        d.addErrback(self.log_err, extra="Failed to get UAID for redeliver")

    def _notify_node(self, result):
        """Checks the result of lookup node to send the notify if the client is
        connected elsewhere now"""
        if not result:
            self.metrics.increment("error.notify_uaid_failure",
                                   tags=self.base_tags)
            return

        node_id = result.get("node_id")
        if not node_id:
            return

        # Send the notify to the node
        url = node_id + "/notif/" + self.uaid
        d = self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
        ).addCallback(IgnoreBody.ignore)
        d.addErrback(self.log_err, extra="Failed to notify node")

    def returnError(self, messageType, reason, statusCode, close=True):
        self.sendJSON({"messageType": messageType,
                       "reason": reason,
                       "status": statusCode})
        if close:
            self.sendClose()

    def sendJSON(self, body):
        self.sendMessage(json.dumps(body).encode('utf8'), False)

    #############################################################
    #                Message Processing Methods
    #############################################################
    def process_hello(self, data):
        # This must be a helo, or we kick the client
        cmd = data.get("messageType")
        if cmd != "hello":
            return self.sendClose()

        if self.uaid:
            return self.returnError("hello", "duplicate hello", 401)

        uaid = data.get("uaid")
        _, uaid = validate_uaid(uaid)
        self.uaid = uaid

        # Default router choice
        router_type = data.get("router_type", "simplepush")
        if not router_type or router_type not in self.ap_settings.routers:
            return self.returnError("hello", "invalid router", "401")

        self.transport.pauseProducing()
        user_item = dict(
            uaid=self.uaid,
            node_id=self.ap_settings.router_url,
            connected_at=self.connected_at,
            router_type=router_type,
            router_data={},
        )
        d = self.deferToThread(self.ap_settings.router.register_user,
                               user_item)
        d.addCallback(self._check_other_nodes)
        d.addErrback(self.err_hello)
        self._register = d
        return d

    def err_hello(self, failure):
        self.transport.resumeProducing()
        self.log_err(failure)
        self.returnError("hello", "error", 503)

    def _check_other_nodes(self, result):
        self.transport.resumeProducing()
        registered, previous = result
        if not registered:
            # Registration failed
            msg = {"messageType": "hello", "reason": "already_connected",
                   "status": 500}
            self.sendMessage(json.dumps(msg).encode('utf8'), False)
            return

        existing = self.ap_settings.clients.get(self.uaid)
        if existing:
            if self.connected_at <= existing.connected_at:
                self.sendClose()
                return
            else:
                existing.sendClose()

        if previous and "node_id" in previous:
            # Get the previous information returned from dynamodb.
            node_id = previous["node_id"]
            last_connect = previous.get("connected_at")
            if last_connect and node_id != self.ap_settings.router_url:
                url = "%s/notif/%s/%s" % (node_id, self.uaid, last_connect)
                d = self.ap_settings.agent.request(
                    "DELETE",
                    url.encode("utf8"),
                )
                d.addErrback(lambda f: f.trap(ConnectError,
                                              ConnectionRefusedError,
                                              UserError))
                d.addErrback(self.log_err,
                             extra="Failed to delete old node")
        self.finish_hello()

    def finish_hello(self, *args):
        self._register = None
        msg = {"messageType": "hello", "uaid": self.uaid, "status": 200}
        self.ap_settings.clients[self.uaid] = self
        self.sendJSON(msg)
        self.metrics.increment("updates.client.hello", tags=self.base_tags)
        self.process_notifications()

    def process_notifications(self):
        # Bail immediately if we are closed.
        if self._should_stop:
            return

        # Are we paused? Try again later.
        if self.paused:
            self.deferToLater(1, self.process_notifications)
            return

        # Are we already running?
        if self._notification_fetch:
            # Cancel the prior, last one wins
            self._notification_fetch.cancel()

        self._check_notifications = False

        # Prevent repeat calls
        d = self.deferToThread(self.ap_settings.storage.fetch_notifications,
                               self.uaid)
        d.addErrback(self.error_notifications)
        d.addCallback(self.finish_notifications)
        self._notification_fetch = d

    def error_notifications(self, fail):
        # If we error'd out on this important check, we drop the connection
        self.log_err(fail)
        self.sendClose()

    def finish_notifications(self, notifs):
        self._notification_fetch = None

        # Are we paused, try again later
        if self.paused:
            self.deferToLater(1, self.process_notifications)

        updates = []
        notifs = notifs or []
        # Track outgoing, screen out things we've seen that weren't
        # ack'd yet
        for s in notifs:
            chid = s['chid']
            version = int(s['version'])
            if self.updates_sent.get(chid, 0) >= version:
                continue
            direct_notif = self.direct_updates.get(chid)
            if direct_notif and direct_notif >= version:
                continue
            elif direct_notif:
                # We're going to send a newer one, ignore the direct older
                # one for acks
                del self.direct_updates[chid]
            self.updates_sent[chid] = version
            updates.append({"channelID": chid, "version": version})
        if updates:
            msg = {"messageType": "notification", "updates": updates}
            self.sendJSON(msg)

        # Were we told to check notifications again?
        if self._check_notifications:
            self._check_notifications = False
            self.deferToLater(1, self.process_notifications)

    def _send_ping(self):
        self.last_ping = time.time()
        self.metrics.increment("updates.client.ping", tags=self.base_tags)
        return self.sendMessage("{}", False)

    def process_ping(self):
        """Adaptive ping processing

        Clients in the wild have a bug that lowers their ping interval to 0. It
        will never increase for them, but if we disconnect them, then they will
        reconnect in 5 seconds. As such, its beneficial for us and the client
        to delay a response to a client pinging fast, but not such that its
        worse than the alternative, reconnecting.

        Therefore we will attempt to send this ping within the 10 second
        timeout many clients already have, based on guesstimating latency from
        the last ping. The last ping is not necessarilly latency, but it will
        allow us to avoid sending too fast, but not waiting too long. The
        practical result is that we will respond to each ping within 0-9 sec
        depending on when we last got a ping.

        """
        now = time.time()
        last_ping_ago = now - self.last_ping
        if last_ping_ago >= 9:
            self._send_ping()
        else:
            return self.deferToLater(9 - last_ping_ago, self._send_ping)

    def process_register(self, data):
        if "channelID" not in data:
            return self.bad_message("register")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("register")
        self.transport.pauseProducing()

        d = self.deferToThread(self.ap_settings.make_endpoint, self.uaid, chid)
        d.addCallback(self.finish_register, chid)
        d.addErrback(self.error_register)
        return d

    def error_register(self, fail):
        self.transport.resumeProducing()
        msg = {"messageType": "register", "status": 500}
        self.sendJSON(msg)

    def finish_register(self, endpoint, chid):
        self.transport.resumeProducing()
        msg = {"messageType": "register",
               "channelID": chid,
               "pushEndpoint": endpoint,
               "status": 200
               }
        self.sendJSON(msg)
        self.metrics.increment("updates.client.register", tags=self.base_tags)

    def process_unregister(self, data):
        if "channelID" not in data:
            return self.bad_message("unregister")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("unregister")

        self.metrics.increment("updates.client.unregister",
                               tags=self.base_tags)

        # Delete any record from storage, we don't wait for this
        d = self.deferToThread(self.ap_settings.storage.delete_notification,
                               self.uaid, chid)
        d.addBoth(self.force_delete, chid)
        data["status"] = 200
        self.sendJSON(data)

    def force_delete(self, result, chid):
        """Forces another delete call through until it works"""
        if isinstance(result, failure.Failure):
            # This is an exception, log it
            self.log_err(result)

        d = self.deferToThread(self.ap_settings.storage.delete_notification,
                               self.uaid, chid)
        d.addErrback(self.force_delete, chid)
        return d

    def ack_update(self, update):
        chid = update.get("channelID")
        version = update.get("version")
        if not chid or not version:
            return

        # If its a direct update, remove it and return
        if self.direct_updates.get(chid) == version:
            del self.direct_updates[chid]
            return

        # Remove the update if version matches
        if self.updates_sent.get(chid) == version:
            del self.updates_sent[chid]
        else:
            return

        # If we ack'd a notification that wasn't direct, delete it
        # Note: Not using self.deferToThread because this should run even if
        # the client dropped
        d = deferToThread(self.ap_settings.storage.delete_notification,
                          self.uaid, chid, version)
        d.addCallback(self.check_ack, self.uaid, chid, version)
        d.addErrback(self.log_err)
        return d

    def process_ack(self, data):
        updates = data.get("updates")
        if not updates or not isinstance(updates, list):
            return

        self.metrics.increment("updates.client.ack", tags=self.base_tags)
        defers = filter(None, map(self.ack_update, updates))

        if defers:
            self.transport.pauseProducing()
            dl = DeferredList(defers)
            dl.addBoth(self.check_missed_notifications, True)
        else:
            self.check_missed_notifications(None)

    def check_ack(self, result, uaid, chid, version):
        if result:
            return None

        # Retry the operation and return its new deferred
        d = deferToThread(self.ap_settings.storage.delete_notification, uaid,
                          chid, version)
        d.addCallback(self.check_ack, uaid, chid, version)
        d.addErrback(self.log_err)
        return d

    def check_missed_notifications(self, results, resume=False):
        if resume:
            # Resume consuming ack's
            self.transport.resumeProducing()

        # Should we check again?
        if self._check_notifications:
            self.process_notifications()

    def bad_message(self, typ):
        msg = {"messageType": typ, "status": 401}
        self.sendJSON(msg)

    ####################################
    # Utility function for external use
    def send_notifications(self, updates):
        toSend = []
        for update in updates:
            chid, version = update["channelID"], update["version"]
            if self.updates_sent.get(chid, 0) >= version or \
               self.direct_updates.get(chid, 0) >= version:
                continue

            # Otherwise we can record we sent this version
            self.direct_updates[chid] = version
            toSend.append(update)

        if toSend:
            msg = {"messageType": "notification", "updates": toSend}
            self.sendJSON(msg)


class RouterHandler(cyclone.web.RequestHandler):
    def put(self, uaid):
        settings = self.ap_settings
        client = settings.clients.get(uaid)
        if not client:
            self.set_status(404)
            settings.metrics.increment("updates.router.disconnected")
            return self.write("Client not connected.")

        if client.paused:
            self.set_status(503)
            settings.metrics.increment("updates.router.busy")
            return self.write("Client busy.")

        updates = json.loads(self.request.body)
        client.send_notifications(updates)
        settings.metrics.increment("updates.router.received")
        return self.write("Client accepted for delivery")


class NotificationHandler(cyclone.web.RequestHandler):
    def put(self, uaid, *args):
        client = self.ap_settings.clients.get(uaid)
        settings = self.ap_settings
        if not client:
            self.set_status(404)
            settings.metrics.increment("updates.notification.disconnected")
            return self.write("Client not connected.")

        if client.paused:
            # Client already busy waiting for stuff, flag for check
            client._check_notifications = True
            self.set_status(202)
            settings.metrics.increment("updates.notification.flagged")
            return self.write("Flagged for Notification check")

        # Client is online and idle, start a notification check
        client.process_notifications()
        settings.metrics.increment("updates.notification.checking")
        self.write("Notification check started")

    def delete(self, uaid, ignored, connectionTime):
        client = self.ap_settings.clients.get(uaid)
        if client and client.connected_at == int(connectionTime):
            client.sendClose()
            return self.write("Terminated duplicate")
