"""Websocket Protocol handler and HTTP Endpoints for Connection Node

Private HTTP Endpoints
======================

These HTTP endpoints are only for communication from endpoint nodes and must
not be publicly exposed.

.. http:put:: /push/(uuid:uaid)

    Send a notification to a connected client with the given `uaid`.

    :statuscode 200: Client is connected and delivery will be attempted.
    :statuscode 404: Client is not connected to this node.
    :statuscode 503: Client is connected, but currently busy.

.. http:put:: /notif/(uuid:uaid)

    Trigger a stored notification check for a connected client.

    :statuscode 200: Client is connected, and has started checking.
    :statuscode 202: Client is connected but busy, will check notifications
                     when not busy.
    :statuscode 404: Client is not connected to this node.

.. http:delete:: /notif/(uuid:uaid)/(int:connected_at)

    Immediately drop a client of this `uaid` if its connection time matches the
    `connected_at` provided.

"""
import json
import random
import time
import uuid
from collections import defaultdict, namedtuple
from functools import wraps

import cyclone.web
from autobahn.twisted.websocket import WebSocketServerProtocol
from boto.dynamodb2.exceptions import ProvisionedThroughputExceededException
from twisted.internet import reactor
from twisted.internet.defer import (
    Deferred,
    DeferredList,
    CancelledError
)
from twisted.web._newclient import ResponseNeverReceived
from twisted.internet.error import (
    ConnectError, ConnectionRefusedError, UserError,
    ConnectionLost, ConnectionDone
)
from twisted.internet.interfaces import IProducer
from twisted.internet.threads import deferToThread
from twisted.protocols import policies
from twisted.python import failure, log
from zope.interface import implements
from twisted.web.resource import Resource

from autopush import __version__
from autopush.db import (
    has_connected_this_month,
    hasher,
    generate_last_connect
)
from autopush.protocol import IgnoreBody
from autopush.utils import validate_uaid, ErrorLogger
from autopush.noseplugin import track_object


def extract_code(data):
    """Extracts and converts a code key if found in data dict"""
    code = data.get("code", None)
    if code and isinstance(code, int):
        code = code
    else:
        code = 0
    return code


def ms_time():
    """Return current time.time call as ms and a Python int"""
    return int(time.time() * 1000)


def periodic_reporter(settings):
    """Twisted Task function that runs every few seconds to emit general
    metrics regarding twisted and client counts"""
    settings.metrics.gauge("update.client.writers",
                           len(reactor.getWriters()))
    settings.metrics.gauge("update.client.readers",
                           len(reactor.getReaders()))
    settings.metrics.gauge("update.client.connections",
                           len(settings.clients))
    settings.metrics.gauge("update.client.ws_connections",
                           settings.factory.countConnections)


def log_exception(func):
    """Exception Logger Decorator for protocol methods"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception:
            self.log_err(failure.Failure())
    return wrapper


class Notification(namedtuple(
                   "Notification",
                   "channel_id data headers version ttl timestamp")):
    """Parsed notification from the request"""


class PushState(object):
    implements(IProducer)

    __slots__ = [
        '_callbacks',
        '_user_agent',
        '_base_tags',
        '_should_stop',
        '_paused',
        'metrics',
        'uaid',
        'uaid_hash',
        'last_ping',
        'check_storage',
        'use_webpush',
        'router_type',
        'wake_data',
        'connected_at',
        'settings',

        # Table rotation
        'message_month',
        'message',
        'rotate_message_table',

        'ping_time_out',
        '_check_notifications',
        '_more_notifications',
        '_notification_fetch',
        '_register',
        'updates_sent',
        'direct_updates',

        # iProducer methods
        'pauseProducing',
        'resumeProducing',
        'stopProducing',
    ]

    def __init__(self, settings, request):
        self._callbacks = []
        self.settings = settings
        host = ""

        if request:
            self._user_agent = request.headers.get("user-agent")
            # Get the name of the server the request asked for.
            host = request.host
        else:
            self._user_agent = None
        self._base_tags = []
        if self._user_agent:
            self._base_tags.append("user_agent:%s" % self._user_agent)
        if host:
            self._base_tags.append("host:%s" % host)

        self._should_stop = False
        self._paused = False
        self.metrics = settings.metrics
        self.metrics.increment("client.socket.connect",
                               tags=self._base_tags or None)
        self.uaid = None
        self.uaid_hash = ""
        self.last_ping = 0
        self.check_storage = False
        self.use_webpush = False
        self.router_type = None
        self.wake_data = None
        self.connected_at = ms_time()
        self.ping_time_out = False

        # Message table rotation initial settings
        self.message_month = settings.current_msg_month
        self.rotate_message_table = False

        self._check_notifications = False
        self._more_notifications = False

        # Hanger for common actions we defer
        self._notification_fetch = None
        self._register = None

        # Reflects Notification's sent that haven't been ack'd
        self.updates_sent = {}

        # Track Notification's we don't need to delete separately
        self.direct_updates = {}

    @property
    def message(self):
        """Property to access the currently used message table"""
        return self.settings.message_tables[self.message_month]

    @property
    def user_agent(self):
        return self._user_agent or "None"

    def pauseProducing(self):
        """IProducer implementation tracking if we should pause output"""
        self._paused = True

    def resumeProducing(self):
        """IProducer implementation tracking when we should resume output"""
        self._paused = False

    def stopProducing(self):
        """IProducer implementation tracking when we should stop"""
        self._paused = True
        self._should_stop = True


class PushServerProtocol(WebSocketServerProtocol, policies.TimeoutMixin):
    """Main Websocket Connection Protocol"""

    # Testing purposes
    parent_class = WebSocketServerProtocol

    # Defer helpers
    def deferToThread(self, func, *args, **kwargs):
        """deferToThread helper that tracks defers outstanding"""
        d = deferToThread(func, *args, **kwargs)
        self.ps._callbacks.append(d)

        def f(result):
            if d in self.ps._callbacks:
                self.ps._callbacks.remove(d)
            return result
        d.addBoth(f)
        return d

    def deferToLater(self, when, func, *args, **kwargs):
        """deferToLater helper that tracks defers outstanding"""
        def cancel(d):
            d._cancelled = True

        d = Deferred(canceller=cancel)
        d._cancelled = False
        self.ps._callbacks.append(d)

        def f():
            if d in self.ps._callbacks:
                self.ps._callbacks.remove(d)

            # Don't run if the deferred was cancelled already
            if d._cancelled:
                return
            try:
                result = func(*args, **kwargs)
                d.callback(result)
            except:
                d.errback(failure.Failure())
        reactor.callLater(when, f)
        return d

    def trap_cancel(self, fail):
        fail.trap(CancelledError)

    def force_retry(self, func, *args, **kwargs):
        """Forcefully retry a function in a thread until it doesn't error

        Note that this does not use ``self.deferToThread``, so this will
        continue to retry even if the client drops.

        """
        def wrapper(result, *w_args, **w_kwargs):
            if isinstance(result, failure.Failure):
                # This is an exception, log it
                self.log_err(result)

            d = deferToThread(func, *args, **kwargs)
            d.addErrback(wrapper)
            return d
        d = deferToThread(func, *args, **kwargs)
        d.addErrback(wrapper)
        return d

    @property
    def base_tags(self):
        """Property that uses None if there's no tags due to a DataDog library
        bug"""
        return self.ps._base_tags if self.ps._base_tags else None

    def log_err(self, failure, **kwargs):
        """Log a twisted failure out through twisted's log.err"""
        log.err(failure, **kwargs)

    @property
    def paused(self):
        """Indicates if we are paused for output production or not"""
        return self.ps._paused

    @log_exception
    def _sendAutoPing(self):
        """Override for sanity checking during auto-ping interval"""
        if not self.ps.uaid:
            # No uaid yet, drop the connection
            self.ps.metrics.increment("client.autoping.no_uaid",
                                      tags=self.base_tags)
            self.sendClose()
        elif self.ap_settings.clients.get(self.ps.uaid) != self:
            # UAID, but we're not in clients anymore for some reason
            self.ps.metrics.increment("client.autoping.invalid_client",
                                      tags=self.base_tags)
            self.sendClose()
        return WebSocketServerProtocol._sendAutoPing(self)

    @log_exception
    def sendClose(self, code=None, reason=None):
        """Override to add tracker that ensures the connection is truly
        torn down"""
        reactor.callLater(10+self.closeHandshakeTimeout, self.nukeConnection)
        return WebSocketServerProtocol.sendClose(self, code, reason)

    @log_exception
    def nukeConnection(self):
        """Aggressive connection shutdown using abortConnection if onClose
        still hadn't run by this point"""
        # Did onClose get called? If so, we shutdown properly, no worries.
        if hasattr(self, "_shutdown_ran"):
            self.ps.metrics.increment("client.success.sendClose",
                                      tags=self.base_tags)
            return

        # Uh-oh, we have not been shut-down properly, report detailed data
        self.ps.metrics.increment("client.error.sendClose_failed",
                                  tags=self.base_tags)

        self.transport.abortConnection()

    @log_exception
    def onConnect(self, request):
        """autobahn onConnect handler for when a connection has started"""
        track_object(self, msg="onConnect Start")
        self.ps = PushState(settings=self.ap_settings, request=request)

        # Setup ourself to handle producing the data
        self.transport.bufferSize = 2 * 1024
        self.transport.registerProducer(self.ps, True)

        if self.ap_settings.hello_timeout > 0:
            self.setTimeout(self.ap_settings.hello_timeout)

    #############################################################
    #                    Connection Methods
    #############################################################
    @log_exception
    def processHandshake(self):
        """Disable host port checking on nonstandard ports since some
        clients are buggy and don't provide it"""
        track_object(self, msg="processHandshake")
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
        """autobahn onMessage processor for incoming messages"""
        if isBinary:
            self.sendClose()
            return

        track_object(self, msg="onMessage")
        data = None
        try:
            data = json.loads(payload.decode('utf8'))
        except:
            pass

        if not isinstance(data, dict):
            self.sendClose()
            return

        # Without a UAID, hello must be next
        if not self.ps.uaid:
            return self.process_hello(data)

        # Ping's get a ping reply
        if data == {}:
            return self.process_ping()

        cmd = data.get("messageType")
        # We're no longer idle, prevent early connection closure.
        self.resetTimeout()
        try:
            if cmd == "hello":
                return self.process_hello(data)
            elif cmd == "register":
                return self.process_register(data)
            elif cmd == "unregister":
                return self.process_unregister(data)
            elif cmd == "ack":
                return self.process_ack(data)
            elif cmd == "nack":
                return self.process_nack(data)
            else:
                self.sendClose()
        finally:
            # Done processing, start idle.
            self.resetTimeout()

    def timeoutConnection(self):
        """Idle timer fired."""
        if self.ps.wake_data:
            return self.sendClose(code=4774, reason="UDP Idle")

        self.sendClose()

    def onAutoPingTimeout(self):
        """Override to track that this shut-down is from a ping timeout"""
        self.ps.ping_time_out = True
        WebSocketServerProtocol.onAutoPingTimeout(self)

    @log_exception
    def onClose(self, wasClean, code, reason):
        """autobahn onClose handler for shutting down the connection and any
        outstanding deferreds related to this connection"""
        try:
            uaid = self.ps.uaid
            self._shutdown_ran = True
            self.ps._should_stop = True
            self.ps._check_notifications = False
        except AttributeError:  # pragma: nocover
            # Sometimes in odd production cases, onClose will be called without
            # onConnect being called to set this up.
            uaid = None

        # Log out the disconnect reason
        if uaid:
            self.cleanUp(wasClean, code, reason)

    def cleanUp(self, wasClean, code, reason):
        """Thorough clean-up method to cancel all remaining deferreds, and send
        connection metrics in"""
        self.ps.metrics.increment("client.socket.disconnect",
                                  tags=self.base_tags)
        elapsed = (ms_time() - self.ps.connected_at) / 1000.0
        self.ps.metrics.timing("client.socket.lifespan", duration=elapsed,
                               tags=self.base_tags)

        # Cleanup our client entry
        if self.ps.uaid and self.ap_settings.clients.get(self.ps.uaid) == self:
            del self.ap_settings.clients[self.ps.uaid]

        # Cancel any outstanding deferreds that weren't already called
        for d in self.ps._callbacks:
            if not d.called:
                d.cancel()

        # Attempt to deliver any notifications not originating from storage
        if self.ps.direct_updates:
            defers = []
            if self.ps.use_webpush:
                for notifs in self.ps.direct_updates.values():
                    notifs = filter(lambda x: x.ttl != 0, notifs)
                    defers.extend(map(self._save_webpush_notif, notifs))
            else:
                for chid, version in self.ps.direct_updates.items():
                    defers.append(self._save_simple_notif(chid, version))

            # Tag on the notifier once everything has been stored
            dl = DeferredList(defers)
            dl.addBoth(self._lookup_node)

        # Delete and remove remaining dicts and lists
        del self.ps.direct_updates
        del self.ps.updates_sent

    def _save_webpush_notif(self, notif):
        """Save a direct_update webpush style notification"""
        return deferToThread(
            self.ps.message.store_message,
            uaid=self.ps.uaid,
            channel_id=notif.channel_id,
            data=notif.data,
            headers=notif.headers,
            message_id=notif.version,
            ttl=notif.ttl,
            timestamp=notif.timestamp,
        ).addErrback(self.log_err)

    def _save_simple_notif(self, channel_id, version):
        """Save a simplepush notification"""
        return deferToThread(
            self.ap_settings.storage.save_notification,
            uaid=self.ps.uaid,
            chid=channel_id,
            version=version,
        ).addErrback(self.log_err)

    def _lookup_node(self, results):
        """Looks up the node to send a notify for it to check storage if
        connected"""
        # Locate the node that has this client connected
        d = deferToThread(
            self.ap_settings.router.get_uaid,
            self.ps.uaid
        )
        d.addCallback(self._notify_node)
        d.addErrback(self.log_err, extra="Failed to get UAID for redeliver")

    def _notify_node(self, result):
        """Checks the result of lookup node to send the notify if the client is
        connected elsewhere now"""
        if not result:
            self.ps.metrics.increment("error.notify_uaid_failure",
                                      tags=self.base_tags)
            return

        node_id = result.get("node_id")
        if not node_id:
            return

        # If it's ourselves, we can stop
        if result.get("connected_at") == self.ps.connected_at:
            return

        # Send the notify to the node
        url = node_id + "/notif/" + self.ps.uaid
        d = self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
        ).addCallback(IgnoreBody.ignore)
        d.addErrback(self.log_err, extra="Failed to notify node")

    def returnError(self, messageType, reason, statusCode, close=True):
        """Return an error to a client, and optionally shut down the connection
        safely"""
        self.sendJSON({"messageType": messageType,
                       "reason": reason,
                       "status": statusCode})
        if close:
            self.sendClose()

    def err_overload(self, failure, message_type):
        """Handle database overloads

        Pause producing to cease incoming notifications while we wait a random
        interval up to 8 seconds before closing down the connection. Most
        clients wait up to 10 seconds for a command, but this is not a
        guarantee, so rather than never reply, we still shut the connection
        down.

        """
        failure.trap(ProvisionedThroughputExceededException)
        self.transport.pauseProducing()
        d = self.deferToLater(random.randrange(4, 9), self.err_finish_overload,
                              message_type)
        d.addErrback(self.trap_cancel)

    def err_finish_overload(self, message_type):
        """Close the connection down and resume consuming input after the
        random interval from a db overload"""
        # Resume producing so we can finish the shutdown
        self.transport.resumeProducing()
        self.returnError(message_type,  "error - overloaded", 503)

    def sendJSON(self, body):
        """Send a Python dict as a JSON string in a websocket message"""

        self.sendMessage(json.dumps(body).encode('utf8'), False)

    #############################################################
    #                Message Processing Methods
    #############################################################
    def process_hello(self, data):
        """Process a hello message"""
        # This must be a helo, or we kick the client
        cmd = data.get("messageType")
        if cmd != "hello":
            return self.sendClose()

        if self.ps.uaid:
            return self.returnError("hello", "duplicate hello", 401)

        uaid = data.get("uaid")
        self.ps.use_webpush = data.get("use_webpush", False)
        self.ps._base_tags.append("use_webpush:%s" %
                                  self.ps.use_webpush)
        self.ps.router_type = "webpush" if self.ps.use_webpush\
                              else "simplepush"
        if self.ps.use_webpush:
            self.ps.updates_sent = defaultdict(lambda: [])
            self.ps.direct_updates = defaultdict(lambda: [])

        existing_user, uaid = validate_uaid(uaid)
        self.ps.uaid = uaid
        self.ps.uaid_hash = hasher(uaid)
        # Check for the special wakeup commands
        if "wakeup_host" in data and "mobilenetwork" in data:
            wakeup_host = data.get("wakeup_host")
            if "ip" in wakeup_host and "port" in wakeup_host:
                mobilenetwork = data.get("mobilenetwork")
                # Normalize the wake info to a single object.
                wake_data = dict(data=dict(ip=wakeup_host["ip"],
                                 port=wakeup_host["port"],
                                 mcc=mobilenetwork.get("mcc", ''),
                                 mnc=mobilenetwork.get("mnc", ''),
                                 netid=mobilenetwork.get("netid", '')))
                self.ps.wake_data = wake_data

        self.transport.pauseProducing()

        d = self._register_user(existing_user)
        d.addCallback(self._copy_new_data)
        d.addCallback(self._check_collision)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.err_overload, "hello")
        d.addErrback(self.err_hello)
        self.ps._register = d
        return d

    def _register_user(self, existing_user=True):
        user_item = dict(
            uaid=self.ps.uaid,
            node_id=self.ap_settings.router_url,
            connected_at=self.ps.connected_at,
            router_type=self.ps.router_type,
        )

        # Write out the last_connect and current_month as applicable for new
        # users
        if not existing_user:
            user_item["last_connect"] = generate_last_connect()
            if self.ps.use_webpush:
                user_item["current_month"] = self.ps.message_month

        # If this connection uses the wakeup mechanism, add it.
        if self.ps.wake_data:
            user_item["wake_data"] = self.ps.wake_data

        return self.deferToThread(self.ap_settings.router.register_user,
                                  user_item)

    def err_hello(self, failure):
        """errBack for hello failures"""
        self.transport.resumeProducing()
        self.log_err(failure)
        self.returnError("hello", "error", 503)

    def _copy_new_data(self, result):
        """Copies data for a new user to the previous record for later
        checks"""
        _, previous, data = result
        if "last_connect" in data:
            previous["last_connect"] = data["last_connect"]
        if "current_month" in data:
            previous["current_month"] = data["current_month"]
        return result

    def _check_collision(self, result):
        """callback to reset the UAID if router registration fails"""
        registered, previous, _ = result

        # Existing user with rotation, or new user getting rotation get to
        # keep their UAID
        existing_webpush_rotator = self.ps.use_webpush and \
            previous.get("current_month")

        # If registered and not a webpush user, continue
        if not self.ps.use_webpush and registered:
            return self._check_other_nodes(result)

        # Or if we are a webpush user and have table rotation already
        if existing_webpush_rotator:
            return self._check_other_nodes(result)

        # If registration fails, try resetting the UAID.
        self.ps.uaid = uuid.uuid4().hex
        d = self._register_user(existing_user=False)
        d.addCallback(self._copy_new_data)
        d.addCallback(self._check_other_nodes)
        return d

    def _check_other_nodes(self, result):
        """callback to check other nodes for clients and send them a delete as
        needed"""
        self.transport.resumeProducing()
        registered, previous, _ = result
        if not registered:
            # Registration failed
            msg = {"messageType": "hello", "reason": "already_connected",
                   "status": 500}
            self.sendJSON(msg)
            return

        # Handle dupes on the same node
        existing = self.ap_settings.clients.get(self.ps.uaid)
        if existing:
            if self.ps.connected_at <= existing.ps.connected_at:
                self.sendClose()
                return
            else:
                existing.sendClose()

        # TODO: Remove this block, issue #245.
        if previous and "node_id" in previous:
            # Get the previous information returned from dynamodb.
            node_id = previous["node_id"]
            last_connect = previous.get("connected_at")
            if last_connect and node_id != self.ap_settings.router_url:
                url = "%s/notif/%s/%s" % (node_id, self.ps.uaid, last_connect)
                d = self.ap_settings.agent.request(
                    "DELETE",
                    url.encode("utf8"),
                )
                d.addErrback(lambda f: f.trap(ConnectError,
                                              ConnectionRefusedError,
                                              UserError,
                                              ResponseNeverReceived,
                                              ConnectionLost,
                                              ConnectionDone))
                d.addErrback(self.log_err,
                             extra="Failed to delete old node")

        # UDP clients are done at this point and timed out to ensure they
        # drop their connection
        timeout = self.ap_settings.wake_timeout if self.ps.wake_data else None
        self.setTimeout(timeout)

        self.finish_hello(previous)

    def _update_last_connect(self, previous):
        """Update last_connect given old router values if needed"""
        if has_connected_this_month(previous):
            return

        self.force_retry(self.ap_settings.router.update_last_connect,
                         self.ps.uaid)

    def finish_hello(self, previous):
        """callback for successful hello message, that sends hello reply"""
        self.ps._register = None
        if self.ps.use_webpush:
            return self._check_message_table_rotation(previous)

        # Check and update last connect
        self._update_last_connect(previous)
        msg = {"messageType": "hello", "uaid": self.ps.uaid, "status": 200}
        if self.autoPingInterval:
            msg["ping"] = self.autoPingInterval

        msg['env'] = self.ap_settings.env
        self.ap_settings.clients[self.ps.uaid] = self
        self.sendJSON(msg)
        self.ps.metrics.increment("updates.client.hello", tags=self.base_tags)
        self.process_notifications()

    def _check_message_table_rotation(self, previous):
        """Check for webpush users if we need to rotate the message table"""
        self.transport.pauseProducing()
        # Check for table rotation
        cur_month = previous.get("current_month")
        if cur_month != self.ps.message_month:
            # Previous month user or new user, flag for message rotation and
            # set the message_month to the router month
            self.ps.message_month = cur_month
            self.ps.rotate_message_table = True

        # Proceed with hello response
        self._finish_webpush_hello()

    def _finish_webpush_hello(self, *ignored_result):
        self.transport.resumeProducing()
        msg = {"messageType": "hello", "uaid": self.ps.uaid, "status": 200}
        if self.autoPingInterval:
            msg["ping"] = self.autoPingInterval
        msg["use_webpush"] = True
        msg['env'] = self.ap_settings.env
        self.ap_settings.clients[self.ps.uaid] = self
        self.sendJSON(msg)
        self.ps.metrics.increment("updates.client.hello", tags=self.base_tags)
        self.process_notifications()

    def process_notifications(self):
        """Run a notification check against storage"""
        # Bail immediately if we are closed.
        if self.ps._should_stop:
            return

        # Are we paused? Try again later.
        if self.paused:
            d = self.deferToLater(1, self.process_notifications)
            d.addErrback(self.trap_cancel)
            return

        # Webpush with any outstanding storage-based must all be cleared
        if self.ps.use_webpush and any(self.ps.updates_sent.values()):
            d = self.deferToLater(1, self.process_notifications)
            d.addErrback(self.trap_cancel)
            return

        # Are we already running?
        if self.ps._notification_fetch:
            # Cancel the prior, last one wins
            self.ps._notification_fetch.cancel()

        self.ps._check_notifications = False
        self.ps._more_notifications = True

        if self.ps.use_webpush:
            d = self.deferToThread(self.ps.message.fetch_messages,
                                   self.ps.uaid)
        else:
            d = self.deferToThread(
                self.ap_settings.storage.fetch_notifications, self.ps.uaid)
        d.addCallback(self.finish_notifications)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.err_overload, "notif")
        d.addErrback(self.error_notifications)
        self.ps._notification_fetch = d

    def error_notifications(self, fail):
        """errBack for notification check failing"""
        # If we error'd out on this important check, we drop the connection
        self.log_err(fail)
        self.sendClose()

    def finish_notifications(self, notifs):
        """callback for processing notifications from storage"""
        self.ps._notification_fetch = None

        # Are we paused, try again later
        if self.paused:
            d = self.deferToLater(1, self.process_notifications)
            d.addErrback(self.trap_cancel)
            return

        # Process notifications differently based on webpush style or not
        if self.ps.use_webpush:
            return self.finish_webpush_notifications(notifs)

        updates = []
        notifs = notifs or []
        # Track outgoing, screen out things we've seen that weren't
        # ack'd yet
        for s in notifs:
            chid = s['chid']
            version = int(s['version'])
            if self._newer_notification_sent(chid, version):
                continue
            if chid in self.ps.direct_updates:
                # We're going to send a newer one, ignore the direct older
                # one for acks
                del self.ps.direct_updates[chid]
            self.ps.updates_sent[chid] = version
            updates.append({"channelID": chid, "version": version})
        if updates:
            msg = {"messageType": "notification", "updates": updates}
            self.sendJSON(msg)

        # Were we told to check notifications again?
        if self.ps._check_notifications:
            self.ps._check_notifications = False
            d = self.deferToLater(1, self.process_notifications)
            d.addErrback(self.trap_cancel)

    def finish_webpush_notifications(self, notifs):
        """webpush notification processor"""
        if not notifs:
            # No more notifications, we can stop.
            self.ps._more_notifications = False
            if self.ps._check_notifications:
                self.ps._check_notifications = False
                d = self.deferToLater(1, self.process_notifications)
                d.addErrback(self.trap_cancel)
                return

            # Not told to check for notifications, do we need to now rotate
            # the message table?
            if self.ps.rotate_message_table:
                self.transport.pauseProducing()
                self.ps.rotate_message_table = False
                self._rotate_message_table()
            return

        # Send out all the notifications
        now = int(time.time())
        for notif in notifs:
            # Split off the chid and message id
            chid, version = notif["chidmessageid"].split(":")

            # If the TTL is too old, don't deliver and fire a delete off
            if not notif["ttl"] or now >= (notif["ttl"]+notif["timestamp"]):
                self.force_retry(
                    self.ps.message.delete_message, self.ps.uaid,
                    chid, version, updateid=notif["updateid"])
                continue

            data = notif.get("data")
            msg = dict(
                messageType="notification",
                channelID=chid,
                version=version + ":" + notif["updateid"],
            )
            if data:
                msg["data"] = data
                msg["headers"] = notif["headers"]
            self.ps.updates_sent[chid].append(
                Notification(channel_id=chid, version=version,
                             data=notif["data"], headers=notif.get("headers"),
                             ttl=notif["ttl"], timestamp=notif["timestamp"])
            )
            self.sendJSON(msg)

    def _rotate_message_table(self):
        """Function to fire off a message table copy of channels + update the
        router current_month entry"""
        self.transport.pauseProducing()
        d = self.deferToThread(self.ps.message.all_channels, self.ps.uaid)
        d.addCallback(self._register_rotated_channels)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.err_overload, "notif")
        d.addErrback(self.log_err)

    def _register_rotated_channels(self, result):
        """Register the channels into a new entry in the current month"""
        # Update the current month now, so that we can save the channels into
        # the right location
        self.ps.message_month = self.ap_settings.current_msg_month

        _, channels = result
        if not channels:
            # No previously registered channels, skip to updating the router
            # table
            return self._update_router_for_message_month(None)

        # Register the channels, then update the router
        d = self.deferToThread(self.ps.message.save_channels, self.ps.uaid,
                               channels)
        d.addCallback(self._update_router_for_message_month)
        return d

    def _update_router_for_message_month(self, result):
        """Update the router for the message month"""
        # This is returned so that the error handling in _rotate_message_table
        # still applies since the deferred chain is fully followed.
        d = self.deferToThread(self.ap_settings.router.update_message_month,
                               self.ps.uaid, self.ps.message_month)
        d.addCallback(lambda x: self.transport.resumeProducing())
        return d

    def _send_ping(self):
        """Helper for ping sending that tracks when the ping was sent"""
        self.ps.last_ping = time.time()
        self.ps.metrics.increment("updates.client.ping", tags=self.base_tags)
        return self.sendMessage("{}", False)

    def process_ping(self):
        """Ping Handling

        Clients in the wild have a bug that lowers their ping interval to 0. It
        will never increase for them, as there is no way to remedy this without
        causing the client to use drastically more battery/data-usage we send
        them a code 4774 close to signify that they should stop until network
        change.

        No other client should ping more than once per minute, or we tell them
        to go away.

        """
        now = time.time()
        last_ping_ago = now - self.ps.last_ping
        if last_ping_ago >= 55:
            self._send_ping()
        else:
            self.sendClose(code=4774)

    def process_register(self, data):
        """Process a register message"""
        if "channelID" not in data:
            return self.bad_message("register")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("register")
        self.transport.pauseProducing()

        d = self.deferToThread(self.ap_settings.make_endpoint, self.ps.uaid,
                               chid, data.get("key"))
        d.addCallback(self.finish_register, chid)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.error_register)
        return d

    def error_register(self, fail):
        """errBack handler for registering to fail"""
        self.transport.resumeProducing()
        msg = {"messageType": "register", "status": 500}
        self.sendJSON(msg)

    def finish_register(self, endpoint, chid):
        """callback for successful endpoint creation, sends register reply"""
        if self.ps.use_webpush:
            d = self.deferToThread(self.ap_settings.message.register_channel,
                                   self.ps.uaid, chid)
            d.addCallback(self.send_register_finish, endpoint, chid)
            # Note: No trap_cancel needed here since the deferred here is
            # returned to process_register which will trap it
            d.addErrback(self.err_overload, "register")
            return d
        else:
            self.send_register_finish(None, endpoint, chid)

    def send_register_finish(self, result, endpoint, chid):
        self.transport.resumeProducing()
        msg = {"messageType": "register",
               "channelID": chid,
               "pushEndpoint": endpoint,
               "status": 200
               }
        self.sendJSON(msg)
        self.ps.metrics.increment("updates.client.register",
                                  tags=self.base_tags)

    def process_unregister(self, data):
        """Process an unregister message"""
        if "channelID" not in data:
            return self.bad_message("unregister")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("unregister")

        self.ps.metrics.increment("updates.client.unregister",
                                  tags=self.base_tags)

        # Log out the unregister if it has a code in it
        if "code" in data:
            code = extract_code(data)
            log.msg("Unregister", channelID=chid, uaid_hash=self.ps.uaid_hash,
                    user_agent=self.ps.user_agent, code=code)

        # Clear out any existing tracked messages for this channel
        if self.ps.use_webpush:
            self.ps.direct_updates[chid] = []
            self.ps.updates_sent[chid] = []
        else:
            self.ps.direct_updates.pop(chid, None)
            self.ps.updates_sent.pop(chid, None)

        if self.ps.use_webpush:
            # Unregister the channel, delete all messages stored
            self.force_retry(self.ap_settings.message.unregister_channel,
                             self.ps.uaid, chid)
            self.force_retry(
                self.ap_settings.message.delete_messages_for_channel,
                self.ps.uaid, chid)
        else:
            # Delete any record from storage, we don't wait for this
            self.force_retry(self.ap_settings.storage.delete_notification,
                             self.ps.uaid, chid)

        data["status"] = 200
        self.sendJSON(data)

    def ack_update(self, update):
        """Helper function for tracking ack'd updates

        Returns either None, if no delete_notification call is needed, or a
        deferred for the delete_notification call if it was needed.

        """
        if not update:
            return

        chid = update.get("channelID")
        version = update.get("version")
        if not chid or not version:
            return

        code = extract_code(update)

        if self.ps.use_webpush:
            return self._handle_webpush_ack(chid, version, code)
        else:
            return self._handle_simple_ack(chid, version, code)

    def _handle_webpush_ack(self, chid, version, code):
        """Handle clearing out a webpush ack"""
        # Split off the updateid if its not a direct update
        version, updateid = version.split(":")

        def ver_filter(update):
            return update.version == version

        found = filter(ver_filter, self.ps.direct_updates[chid])
        if found:
            msg = found[0]
            size = len(msg.data) if msg.data else 0
            log.msg("Ack", router_key="webpush", channelID=chid,
                    message_id=version, message_source="direct",
                    message_size=size, uaid_hash=self.ps.uaid_hash,
                    user_agent=self.ps.user_agent, code=code)
            self.ps.direct_updates[chid].remove(msg)
            return

        found = filter(ver_filter, self.ps.updates_sent[chid])
        if found:
            msg = found[0]
            size = len(msg.data) if msg.data else 0
            log.msg("Ack", router_key="webpush", channelID=chid,
                    message_id=version, message_source="stored",
                    message_size=size, uaid_hash=self.ps.uaid_hash,
                    user_agent=self.ps.user_agent, code=code)
            d = self.force_retry(self.ps.message.delete_message,
                                 uaid=self.ps.uaid,
                                 channel_id=chid,
                                 message_id=version,
                                 updateid=updateid)
            # We don't remove the update until we know the delete ran
            # This is because we don't use range queries on dynamodb and we
            # need to make sure this notification is deleted from the db before
            # we query it again (to avoid dupes).
            d.addBoth(self._handle_webpush_update_remove, chid, msg)
            return d

    def _handle_webpush_update_remove(self, result, chid, notif):
        """Handle clearing out the updates_sent

        It's possible the client may leave before this runs, so this is
        wrapped in a try/except in case the tear-down of self has started.

        """
        try:
            self.ps.updates_sent[chid].remove(notif)
        except (AttributeError, ValueError):
            pass

    def _handle_simple_ack(self, chid, version, code):
        """Handle clearing out a simple ack"""
        if chid in self.ps.direct_updates and \
           self.ps.direct_updates[chid] <= version:
            del self.ps.direct_updates[chid]
            log.msg("Ack", router_key="simplepush", channelID=chid,
                    message_id=version, message_source="direct",
                    uaid_hash=self.ps.uaid_hash,
                    user_agent=self.ps.user_agent, code=code)
            return
        log.msg("Ack", router_key="simplepush", channelID=chid,
                message_id=version, message_source="stored",
                uaid_hash=self.ps.uaid_hash,
                user_agent=self.ps.user_agent, code=code)
        if chid in self.ps.updates_sent and \
           self.ps.updates_sent[chid] <= version:
            del self.ps.updates_sent[chid]
        else:
            return
        return self.force_retry(self.ap_settings.storage.delete_notification,
                                self.ps.uaid, chid, version)

    def process_ack(self, data):
        """Process an ack message, delete notifications from storage if
        needed"""
        updates = data.get("updates")
        if not updates or not isinstance(updates, list):
            return

        self.ps.metrics.increment("updates.client.ack", tags=self.base_tags)
        defers = filter(None, map(self.ack_update, updates))

        if defers:
            self.transport.pauseProducing()
            dl = DeferredList(defers)
            dl.addBoth(self.check_missed_notifications, True)
        else:
            self.check_missed_notifications(None)

    def process_nack(self, data):
        """Process a nack message and log its contents"""
        code = extract_code(data)
        version = data.get("version")
        if not version:
            return

        version, updateid = version.split(":")

        log.msg("Nack", uaid_hash=self.ps.uaid_hash,
                user_agent=self.ps.user_agent, message_id=version,
                code=code)

    def check_missed_notifications(self, results, resume=False):
        """Check to see if notifications were missed"""
        if resume:
            # Resume consuming ack's
            self.transport.resumeProducing()

        # Abort if stopped
        if self.ps._should_stop:
            return

        # When using webpush, we don't check again if we have outstanding
        # notifications
        if self.ps.use_webpush and any(self.ps.updates_sent.values()):
            return

        # Should we check again?
        if self.ps._check_notifications or self.ps._more_notifications:
            self.process_notifications()

    def bad_message(self, typ):
        """Error helper for sending a 401 status back"""
        msg = {"messageType": typ, "status": 401}
        self.sendJSON(msg)

    def _newer_notification_sent(self, channel_id, version):
        """Returns whether a newer channel_id/version has already been sent"""
        return self.ps.updates_sent.get(channel_id, 0) > version or \
            self.ps.direct_updates.get(channel_id, 0) > version

    ####################################
    # Utility function for external use
    def send_notifications(self, update):
        """Utility function for external use

        This function is called by the HTTP handler to deliver incoming
        notifications from an endpoint.

        """
        chid, version = (update["channelID"], update["version"])
        if not self.ps.use_webpush and \
           self._newer_notification_sent(chid, version):
            return

        if self.ps.use_webpush:
            response = dict(
                messageType="notification",
                channelID=chid,
                version="%s:" % version,
            )
            data = update.get("data")
            if data:
                response["data"] = data
                response["headers"] = update["headers"]
            self.ps.direct_updates[chid].append(
                Notification(channel_id=chid, version=version,
                             data=data, headers=update.get("headers"),
                             ttl=update["ttl"], timestamp=update["timestamp"])
            )
            self.sendJSON(response)
        else:
            self.ps.direct_updates[chid] = version
            msg = {"messageType": "notification", "updates": [update]}
            self.sendJSON(msg)


class RouterHandler(cyclone.web.RequestHandler, ErrorLogger):
    """Router Handler

    Handles routing a notification to a connected client from an endpoint.

    """

    def put(self, uaid):
        """HTTP Put

        Attempt delivery of a notification to a connected client.

        """
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

        update = json.loads(self.request.body)
        client.send_notifications(update)
        settings.metrics.increment("updates.router.received")
        return self.write("Client accepted for delivery")


class NotificationHandler(cyclone.web.RequestHandler, ErrorLogger):

    def put(self, uaid, *args):
        """HTTP Put

        Notify a connected client that it should check storage for new
        notifications.

        """
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
        """HTTP Delete

        Drop a connected client as the client has connected to a new node.

        """
        client = self.ap_settings.clients.get(uaid)
        if client and client.ps.connected_at == int(connectionTime):
            client.sendClose()
            return self.write("Terminated duplicate")


class DefaultResource(Resource):
    """Delegates rendering to a default resource."""
    def __init__(self, resource):
        Resource.__init__(self)
        self.resource = resource

    def getChild(self, path, request):
        return self.resource

    def render(self, request):  # pragma: nocover
        return self.resource.render(request)


class StatusResource(Resource):
    isLeaf = True

    def render(self, request):
        request.setResponseCode(200)
        request.setHeader("content-type", "application/json")
        return json.dumps({
            "status": "OK",
            "version": __version__,
        })
