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
import time
import uuid
from collections import defaultdict
from functools import partial, wraps
from random import randrange

import attr
from attr import (
    Factory,
    attrs,
    attrib
)
from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import (
    WebSocketServerFactory,
    WebSocketServerProtocol
)
from autobahn.websocket.protocol import ConnectionRequest  # noqa
from botocore.exceptions import ClientError
from botocore.vendored.requests.packages import urllib3
from twisted.internet import reactor
from twisted.internet.defer import (
    Deferred,
    DeferredList,
    CancelledError
)
from twisted.internet.error import (
    ConnectError,
    ConnectionClosed,
    DNSLookupError)
from twisted.internet.interfaces import IProducer
from twisted.internet.threads import deferToThread
from twisted.logger import Logger
from twisted.protocols import policies
from twisted.python import failure
from twisted.web._newclient import ResponseFailed
from twisted.web.client import Agent  # noqa
from twisted.web.resource import Resource
from twisted.web.server import Site
from typing import (  # noqa
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
)
from zope.interface import implementer

from autopush import __version__
from autopush.base import BaseHandler
from autopush.config import AutopushConfig  # noqa
from autopush.db import (
    has_connected_this_month,
    hasher,
    generate_last_connect,
)
from autopush.db import DatabaseManager, Message  # noqa
from autopush.exceptions import MessageOverloadException, ItemNotFound
from autopush.noseplugin import track_object
from autopush.protocol import IgnoreBody
from autopush.metrics import IMetrics  # noqa
from autopush.ssl import AutopushSSLContextFactory  # noqa
from autopush.utils import (
    parse_user_agent,
    validate_uaid,
    WebPushNotification,
    ms_time
)


USER_RECORD_VERSION = 1
DEFAULT_WS_ERR = "http://autopush.readthedocs.io/en/" \
                 "latest/api/websocket.html#private-http-endpoint"
# codes expected from the client (and emitted as a metric tag)
NACK_CODES = range(301, 304)


def extract_code(data):
    """Extracts and converts a code key if found in data dict"""
    code = data.get("code", None)
    if code and isinstance(code, int):
        code = code
    else:
        code = 0
    return code


def log_exception(func):
    """Exception Logger Decorator for protocol methods"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception:
            if self._log_exc:
                self.log_failure(failure.Failure())
            else:
                raise
    return wrapper


@attrs(slots=True)
class SessionStatistics(object):
    """Websocket Session Statistics

    Tracks statistics about the session that are logged when the websocket
    session has been closed.

    """
    # User data
    uaid_hash = attrib(default="")  # type: str
    uaid_reset = attrib(default=False)  # type: bool
    existing_uaid = attrib(default=False)  # type: bool
    connection_type = attrib(default="")  # type: str
    host = attrib(default="")  # type: str
    ua_os_family = attrib(default="")  # type: str
    ua_os_ver = attrib(default="")  # type: str
    ua_browser_family = attrib(default="")  # type: str
    ua_browser_ver = attrib(default="")  # type: str
    connection_time = attrib(default=0)  # type: int

    # Usage data
    direct_acked = attrib(default=0)  # type: int
    direct_storage = attrib(default=0)  # type: int
    stored_retrieved = attrib(default=0)  # type: int
    stored_acked = attrib(default=0)  # type: int
    nacks = attrib(default=0)  # type: int
    unregisters = attrib(default=0)  # type: int
    registers = attrib(default=0)  # type: int

    def logging_data(self):
        # type: () -> Dict[str, Any]
        return attr.asdict(self)


@implementer(IProducer)
@attrs(slots=True)
class PushState(object):
    """Compact storage of a PushProtocolConnection's state"""

    db = attrib()  # type: DatabaseManager
    _callbacks = attrib(default=Factory(list))  # type: List[Deferred]

    stats = attrib(
        default=Factory(SessionStatistics))  # type: SessionStatistics

    _user_agent = attrib(default=None)  # type: Optional[str]
    _base_tags = attrib(default=Factory(list))  # type: List[str]
    raw_agent = attrib(default=Factory(dict))  # type: Optional[Dict[str, str]]

    _should_stop = attrib(default=False)  # type: bool
    _paused = attrib(default=False)  # type: bool

    _uaid_obj = attrib(default=None)  # type: Optional[uuid.UUID]
    _uaid_hash = attrib(default=None)  # type: Optional[str]

    last_ping = attrib(default=0.0)  # type: float
    check_storage = attrib(default=False)  # type: bool
    router_type = attrib(default=None)  # type: Optional[str]
    connected_at = attrib(default=Factory(ms_time))  # type: float
    ping_time_out = attrib(default=False)  # type: bool

    # Message table rotation
    message_month = attrib(init=False)  # type: str
    rotate_message_table = attrib(default=False)  # type: bool

    _check_notifications = attrib(default=False)  # type: bool
    _more_notifications = attrib(default=False)  # type: bool

    # Timestamped message handling defaults
    scan_timestamps = attrib(default=False)  # type: bool
    current_timestamp = attrib(default=None)  # type: Optional[int]

    # Hanger for common actions we defer
    _notification_fetch = attrib(default=None)  # type: Optional[Deferred]
    _register = attrib(default=None)  # type: Optional[Deferred]

    # Reflects Notification's sent that haven't been ack'd This is
    # simplepush style by default
    updates_sent = attrib(default=Factory(dict))  # type: Dict

    # Track Notification's we don't need to delete separately This is
    # simplepush style by default
    direct_updates = attrib(default=Factory(dict))  # type: Dict

    # Whether this record should be reset after delivering stored
    # messages
    _reset_uaid = attrib(default=False)  # type: bool

    @classmethod
    def from_request(cls, request, **kwargs):
        # type: (ConnectionRequest, **Any) -> PushState
        return cls(
            user_agent=request.headers.get("user-agent"),
            stats=SessionStatistics(host=request.host),
            **kwargs
        )

    def __attrs_post_init__(self):
        """Initialize PushState"""
        if self._user_agent:
            dd_tags, self.raw_agent = parse_user_agent(self._user_agent)
            for tag_name, tag_value in dd_tags.items():
                setattr(self.stats, tag_name, tag_value)
                self._base_tags.append("%s:%s" % (tag_name, tag_value))
            self.stats.ua_os_ver = self.raw_agent["ua_os_ver"]
            self.stats.ua_browser_ver = self.raw_agent["ua_browser_ver"]
        if self.stats.host:
            self._base_tags.append("host:%s" % self.stats.host)

        # Message table rotation initial settings
        self.message_month = self.db.current_msg_month

        self.reset_uaid = False

    @property
    def user_agent(self):
        # type: () -> str
        return self._user_agent or "None"

    @property
    def reset_uaid(self):
        # type: () -> bool
        return self._reset_uaid

    @reset_uaid.setter
    def reset_uaid(self, value):
        if value:
            self._reset_uaid = True
            self.stats.uaid_reset = True
        else:
            self._reset_uaid = False

    @property
    def uaid_obj(self):
        # type: () -> Optional[uuid.UUID]
        return self._uaid_obj

    @property
    def uaid_hash(self):
        # type: () -> str
        return self._uaid_hash

    @property
    def uaid(self):
        # type: () -> Optional[str]
        return self._uaid_obj.hex if self._uaid_obj else None

    @uaid.setter
    def uaid(self, value):
        self._uaid_obj = uuid.UUID(value) if value else None
        self._uaid_hash = hasher(value) if value else ""
        self.stats.uaid_hash = self._uaid_hash

    def init_connection(self):
        """Set the connection type for the client"""
        self._base_tags.append("use_webpush:True")
        self.router_type = self.stats.connection_type = "webpush"

        # Update our message tracking for webpush
        self.updates_sent = defaultdict(lambda: [])
        self.direct_updates = defaultdict(lambda: [])

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
    log = Logger()

    # Testing purposes
    parent_class = WebSocketServerProtocol
    randrange = randrange
    _log_exc = True
    sent_notification_count = 0

    @property
    def conf(self):
        # type: () -> AutopushConfig
        return self.factory.conf

    @property
    def db(self):
        # type: () -> DatabaseManager
        return self.factory.db

    @property
    def metrics(self):
        # type: () -> IMetrics
        return self.db.metrics

    # Defer helpers
    def deferToThread(self, func, *args, **kwargs):
        # type (Callable[..., Any], *Any, **Any) -> Deferred
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
        # type: (float, Callable[..., Any], *Any, **Any) -> Deferred
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
            except Exception:
                d.errback(failure.Failure())
        reactor.callLater(when, f)
        return d

    def trap_cancel(self, fail):
        fail.trap(CancelledError)

    def trap_connection_err(self, fail):
        fail.trap(ConnectError, ConnectionClosed, ResponseFailed,
                  DNSLookupError)

    def trap_boto3_err(self, fail):
        # trap boto3 ConnectTimeoutError in retry
        fail.trap(urllib3.exceptions.ConnectTimeoutError)

    def force_retry(self, func, *args, **kwargs):
        # type: (Callable[..., Any], *Any, **Any) -> Deferred
        """Forcefully retry a function in a thread until it doesn't error

        Note that this does not use ``self.deferToThread``, so this will
        continue to retry even if the client drops.

        """
        def wrapper(result, *w_args, **w_kwargs):
            if isinstance(result, failure.Failure):
                # This is an exception, log it
                self.log_failure(result)

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

    def log_failure(self, failure, **kwargs):
        """Log a twisted failure out through twisted's log.failure"""
        self.log.failure(format="Unexpected error", failure=failure, **kwargs)

    @property
    def paused(self):
        """Indicates if we are paused for output production or not"""
        return self.ps._paused

    @log_exception
    def _sendAutoPing(self):
        """Override for sanity checking during auto-ping interval"""
        # Note: it's possible (but tracking information has yet to prove) that
        # a websocket connection could persist longer than the message record
        # expiration time (~30d), which might cause some problems. Most
        # websocket connections time out far, far earlier than that, which
        # resets the record expiration times.
        if not self.ps.uaid:
            # No uaid yet, drop the connection
            self.sendClose()
        elif self.factory.clients.get(self.ps.uaid) != self:
            # UAID, but we're not in clients anymore for some reason
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
            return
        self.transport.abortConnection()

    @log_exception
    def onConnect(self, request):
        """autobahn onConnect handler for when a connection has started"""
        track_object(self, msg="onConnect Start")
        self.ps = PushState.from_request(request=request, db=self.db)

        # Setup ourself to handle producing the data
        self.transport.bufferSize = 2 * 1024
        try:
            self.transport.registerProducer(self.ps, True)
        except RuntimeError:
            # HACK: Autobahn/twisted/h2 hacks mess this up, ensure we can
            # register the producer
            self.transport.unregisterProducer()
            self.transport.registerProducer(self.ps, True)

        if self.conf.hello_timeout > 0:
            self.setTimeout(self.conf.hello_timeout)

    #############################################################
    #                    Connection Methods
    #############################################################
    @log_exception
    def processHandshake(self):
        """Disable host port checking on nonstandard ports since some
        clients are buggy and don't provide it"""
        track_object(self, msg="processHandshake")
        port = self.conf.port
        hide = port != 80 and port != 443
        old_port = self.factory.externalPort
        try:
            if hide:
                self.factory.externalPort = None
            return self.parent_class.processHandshake(self)
        except UnicodeEncodeError:
            self.failHandshake("Error reading handshake data")
        finally:
            if hide:
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
        except (TypeError, ValueError):
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
        elapsed = (ms_time() - self.ps.connected_at) / 1000.0
        self.metrics.timing("ua.connection.lifespan", duration=elapsed,
                            tags=self.base_tags)
        self.ps.stats.connection_time = int(elapsed)

        # Cleanup our client entry
        if self.ps.uaid and self.factory.clients.get(self.ps.uaid) == self:
            del self.factory.clients[self.ps.uaid]

        # Cancel any outstanding deferreds that weren't already called
        for d in self.ps._callbacks:
            if not d.called:
                d.cancel()

        # Attempt to deliver any notifications not originating from storage
        if self.ps.direct_updates:
            defers = []
            for notifs in self.ps.direct_updates.values():
                notifs = filter(lambda x: x.ttl != 0, notifs)
                self.ps.stats.direct_storage += len(notifs)
                defers.extend(map(self._save_webpush_notif, notifs))

            # Tag on the notifier once everything has been stored
            dl = DeferredList(defers)
            dl.addBoth(self._lookup_node)

        # Delete and remove remaining dicts and lists
        del self.ps.direct_updates
        del self.ps.updates_sent

        # Log out sessions stats
        self.log.info("Session", **self.ps.stats.logging_data())

    def _save_webpush_notif(self, notif):
        """Save a direct_update webpush style notification"""
        message = self.db.message_table(self.ps.message_month)
        return deferToThread(message.store_message,
                             notif).addErrback(self.log_failure)

    def _lookup_node(self, results):
        """Looks up the node to send a notify for it to check storage if
        connected"""
        # Locate the node that has this client connected
        d = deferToThread(self.db.router.get_uaid, self.ps.uaid)
        d.addCallback(self._notify_node)
        d.addErrback(self._trap_uaid_not_found)
        d.addErrback(self.log_failure,
                     extra="Failed to get UAID for redeliver")

    def _trap_uaid_not_found(self, fail):
        # type: (failure.Failure) -> None
        """Traps UAID not found error"""
        fail.trap(ItemNotFound)

    def _notify_node(self, result):
        """Checks the result of lookup node to send the notify if the client is
        connected elsewhere now"""
        if not result:
            return
        node_id = result.get("node_id")
        if not node_id:
            return

        # If it's ourselves, we can stop
        if result.get("connected_at") == self.ps.connected_at:
            return

        # Send the notify to the node
        url = node_id + "/notif/" + self.ps.uaid
        d = self.factory.agent.request(
            "PUT",
            url.encode("utf8"),
        ).addCallback(IgnoreBody.ignore)
        d.addErrback(self.trap_connection_err)
        d.addErrback(self.trap_boto3_err)
        d.addErrback(self.log_failure, extra="Failed to notify node")

    def returnError(self, messageType, reason, statusCode, close=True,
                    url=DEFAULT_WS_ERR):
        """Return an error to a client, and optionally shut down the connection
        safely"""
        send = {"messageType": messageType, "reason": reason,
                "status": statusCode}
        if url:
            send["more_info"] = url
        self.sendJSON(send)
        if close:
            self.sendClose()

    def error_overload(self, failure, message_type, disconnect=True):
        """Handle database overloads and errors

        If ``disconnect`` is False, the an overload error is returned and the
        client is not disconnected.

        Otherwise, pause producing to cease incoming notifications while we
        wait a random interval up to 8 seconds before closing down the
        connection. Most clients wait up to 10 seconds for a command,
        but this is not a guarantee, so rather than never reply, we still
        shut the connection down.

        :param disconnect: Whether the client should be disconnected or not.

        """
        failure.trap(ClientError)

        if disconnect:
            self.transport.pauseProducing()
            d = self.deferToLater(self.randrange(4, 9),
                                  self.error_finish_overload, message_type)
            d.addErrback(self.trap_cancel)
        else:
            send = {"messageType": "error", "reason": "overloaded",
                    "status": 503}
            self.sendJSON(send)

    def error_finish_overload(self, message_type):
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

        if not data.get("use_webpush", False):
            return self.returnError("hello", "Simplepush not supported", 401)
        self.ps.init_connection()

        uaid = data.get("uaid")
        existing_user, uaid = validate_uaid(uaid)
        self.ps.uaid = uaid
        self.ps.stats.existing_uaid = existing_user
        self.transport.pauseProducing()

        d = self.deferToThread(self._register_user, existing_user)
        d.addCallback(self._check_other_nodes)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.error_overload, "hello")
        d.addErrback(self.error_hello)
        self.ps._register = d
        return d

    def _register_user(self, existing_user=True):
        """Register a returning or new user

        :type existing_user: bool

        """
        # If it's an existing user, verify the record is valid
        user_item = None
        if existing_user:
            user_item = self._verify_user_record()

        if not user_item:
            # No valid user record, consider this a new user
            self.ps.uaid = uuid.uuid4().hex
            self.ps.stats.uaid_reset = True
            user_item = dict(
                uaid=self.ps.uaid, node_id=self.conf.router_url,
                connected_at=self.ps.connected_at,
                router_type=self.ps.router_type,
                last_connect=generate_last_connect(),
                record_version=USER_RECORD_VERSION,
            )
            user_item["current_month"] = self.ps.message_month

        return self.db.router.register_user(user_item)

    def _verify_user_record(self):
        """Verify a user record is valid

        Returns a record that is ready for registering in the database if
        the user record was found.

        :rtype: :class:`~boto.dynamodb2.items.Item` or None

        """
        try:
            record = self.db.router.get_uaid(self.ps.uaid)
        except ItemNotFound:
            return None

        # All records must have a router_type and connected_at, in some odd
        # cases a record exists for some users that doesn't
        if "router_type" not in record or "connected_at" not in record:
            self.log.debug(format="Dropping User", code=104,
                           uaid_hash=self.ps.uaid_hash,
                           uaid_record=repr(record))
            tags = ['code:104']
            self.metrics.increment("ua.expiration", tags=tags)
            self.force_retry(self.db.router.drop_user, self.ps.uaid)
            return None

        # Validate webpush records
        # Current month must exist and be a valid prior month
        if ("current_month" not in record) or record["current_month"] \
                not in self.db.message_tables:
            self.log.debug(format="Dropping User", code=105,
                           uaid_hash=self.ps.uaid_hash,
                           uaid_record=repr(record))
            self.force_retry(self.db.router.drop_user, self.ps.uaid)
            tags = ['code:105']
            self.metrics.increment("ua.expiration", tags=tags)
            return None

        # Determine if message table rotation is needed
        if record["current_month"] != self.ps.message_month:
            self.ps.message_month = record["current_month"]
            self.ps.rotate_message_table = True

        # Include and update last_connect if needed, otherwise exclude
        if has_connected_this_month(record):
            del record["last_connect"]
        else:
            record["last_connect"] = generate_last_connect()

        # Determine if this is missing a record version
        if ("record_version" not in record or
                int(record["record_version"]) < USER_RECORD_VERSION):
            self.ps.reset_uaid = True

        # Update the node_id, connected_at for this node/connected_at
        record["node_id"] = self.conf.router_url
        record["connected_at"] = self.ps.connected_at
        return record

    def error_hello(self, failure):
        """errBack for hello failures"""
        self.transport.resumeProducing()
        self.log_failure(failure)
        self.returnError("hello", "error", 503)

    def _check_other_nodes(self, result, url=DEFAULT_WS_ERR):
        """callback to check other nodes for clients and send them a delete as
        needed"""
        self.transport.resumeProducing()

        registered, previous = result
        if not registered:
            # Registration failed
            msg = {"messageType": "hello", "reason": "already_connected",
                   "status": 500, "more_info": url}
            self.sendJSON(msg)
            return

        # Handle dupes on the same node
        existing = self.factory.clients.get(self.ps.uaid)
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
            if last_connect and node_id != self.conf.router_url:
                url = "%s/notif/%s/%s" % (node_id, self.ps.uaid, last_connect)
                d = self.factory.agent.request("DELETE", url.encode("utf8"))
                d.addErrback(self.trap_connection_err)
                d.addErrback(self.trap_boto3_err)
                d.addErrback(self.log_failure,
                             extra="Failed to delete old node")

        self.finish_hello(previous)

    def finish_hello(self, previous):
        """callback for successful hello message, that sends hello reply"""
        self.ps._register = None
        msg = {"messageType": "hello", "uaid": self.ps.uaid, "status": 200,
               "use_webpush": True}

        if self.autoPingInterval:
            msg["ping"] = self.autoPingInterval

        msg['env'] = self.conf.env
        self.factory.clients[self.ps.uaid] = self
        self.sendJSON(msg)
        self.log.debug(format="hello", uaid_hash=self.ps.uaid_hash,
                       **self.ps.raw_agent)
        self.metrics.increment("ua.command.hello")
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
        if any(self.ps.updates_sent.values()):
            d = self.deferToLater(1, self.process_notifications)
            d.addErrback(self.trap_cancel)
            return

        # Are we already running?
        if self.ps._notification_fetch:
            # Cancel the prior, last one wins
            self.ps._notification_fetch.cancel()

        self.ps._check_notifications = False
        self.ps._more_notifications = True

        d = self.deferToThread(self.webpush_fetch)
        d.addCallback(self.finish_notifications)
        d.addErrback(self.error_notification_overload)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.error_message_overload)
        # The following errback closes the connection. It must be the last
        # errback in the chain.
        d.addErrback(self.error_notifications)
        self.ps._notification_fetch = d

    def webpush_fetch(self):
        """Helper to return an appropriate function to fetch messages"""
        message = self.db.message_table(self.ps.message_month)
        if self.ps.scan_timestamps:
            return partial(message.fetch_timestamp_messages,
                           self.ps.uaid_obj,
                           self.ps.current_timestamp)
        else:
            return partial(message.fetch_messages,
                           self.ps.uaid_obj)

    def error_notifications(self, fail):
        """errBack for notification check failing"""
        # If we error'd out on this important check, we drop the connection
        self.log_failure(fail)
        self.sendClose()

    def error_notification_overload(self, fail):
        """errBack for provisioned errors during notification check"""
        fail.trap(ClientError)

        if (fail.value.response["Error"]["Code"] !=
                "ProvisionedThroughputExceededException"):
            return fail  # pragma nocover
        # Silently ignore the error, and reschedule the notification check
        # to run up to a minute in the future to distribute load farther
        # out
        d = self.deferToLater(randrange(5, 60), self.process_notifications)
        d.addErrback(self.trap_cancel)

    def error_message_overload(self, fail):
        """errBack for handling excessive messages per UAID"""
        fail.trap(MessageOverloadException)
        self.force_retry(self.db.router.drop_user, self.ps.uaid)
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
        return self.finish_webpush_notifications(notifs)

    def finish_webpush_notifications(self, result):
        # type: (Tuple[str, List[WebPushNotification]]) -> None
        """WebPush notification processor"""
        timestamp, notifs = result

        # If there's a timestamp, update our current one to it
        if timestamp:
            self.ps.current_timestamp = timestamp

        if not notifs:
            # No more notifications, check timestamped?
            if not self.ps.scan_timestamps:
                # Scan for timestamped then
                self.ps.scan_timestamps = True
                d = self.deferToLater(0, self.process_notifications)
                d.addErrback(self.trap_cancel)
                return

            # No more notifications, and we've scanned timestamped.
            self.ps._more_notifications = False
            self.ps.scan_timestamps = False
            self.sent_notification_count = 0
            if self.ps._check_notifications:
                # Told to check again, start over
                self.ps._check_notifications = False
                d = self.deferToLater(1, self.process_notifications)
                d.addErrback(self.trap_cancel)
                return

            # Told to reset the user?
            if self.ps.reset_uaid:
                self.force_retry(self.db.router.drop_user, self.ps.uaid)
                self.sendClose()

            # Not told to check for notifications, do we need to now rotate
            # the message table?
            if self.ps.rotate_message_table:
                self._rotate_message_table()
            return

        # Send out all the notifications
        now = int(time.time())
        messages_sent = False
        message = self.db.message_table(self.ps.message_month)
        for notif in notifs:
            self.ps.stats.stored_retrieved += 1
            # If the TTL is too old, don't deliver and fire a delete off
            if notif.expired(at_time=now):
                if not notif.sortkey_timestamp:
                    # Delete non-timestamped messages
                    self.force_retry(message.delete_message,
                                     notif)

                # nocover here as coverage gets confused on the line below
                # for unknown reasons
                continue  # pragma: nocover

            self.ps.updates_sent[str(notif.channel_id)].append(notif)
            msg = notif.websocket_format()
            messages_sent = True
            self.sent_notification_count += 1
            if self.sent_notification_count > self.conf.msg_limit:
                raise MessageOverloadException()
            self.emit_send_metrics(notif)
            self.sendJSON(msg)

        # Did we send any messages?
        if messages_sent:
            return

        # No messages sent, update the record if needed
        if self.ps.current_timestamp:
            self.force_retry(
                message.update_last_message_read,
                self.ps.uaid_obj,
                self.ps.current_timestamp)

        # Schedule a new process check
        self.check_missed_notifications(None)

    def _rotate_message_table(self):
        """Function to fire off a message table copy of channels + update the
        router current_month entry"""
        self.transport.pauseProducing()
        d = self.deferToThread(self._monthly_transition)
        d.addCallback(self._finish_monthly_transition)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.error_monthly_rotation_overload)
        d.addErrback(self.error_notifications)

    def _monthly_transition(self):
        """Transition the client to use a new message month

        Utilized to migrate a users channels to a new message month and
        update the router record reflecting the proper month.

        This is a blocking function that does *not* run on the event loop.

        """
        # Get the current channels for this month
        message = self.db.message_table(self.ps.message_month)
        _, channels = message.all_channels(self.ps.uaid)

        # Get the current message month
        cur_month = self.db.current_msg_month
        if channels:
            # Save the current channels into this months message table
            msg_table = self.db.message_table(cur_month)
            msg_table.save_channels(self.ps.uaid, channels)

        # Finally, update the route message month
        self.db.router.update_message_month(self.ps.uaid, cur_month)

    def _finish_monthly_transition(self, result):
        """Mark the client as successfully transitioned and resume"""
        # Update the current month now that we've moved forward a month
        self.ps.message_month = self.db.current_msg_month
        self.ps.rotate_message_table = False
        self.transport.resumeProducing()

    def error_monthly_rotation_overload(self, fail):
        """Capture overload on monthly table rotation attempt

        If a provision exceeded error hits while attempting monthly table
        rotation, schedule it all over and re-scan the messages. Normal
        websocket client flow is returned in the meantime.

        """
        fail.trap(ClientError)
        if (fail.value.response['Error']['Code'] !=
                "ProvisionedThroughputExceededException"):
            return fail  # pragma nocover
        self.transport.resumeProducing()
        d = self.deferToLater(randrange(1, 30*60), self.process_notifications)
        d.addErrback(self.trap_cancel)

    def _send_ping(self):
        """Helper for ping sending that tracks when the ping was sent"""
        self.ps.last_ping = time.time()
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
            if str(uuid.UUID(chid)) != chid:
                return self.bad_message("register", "Bad UUID format, use"
                                        "lower case, dashed format")
        except (ValueError, TypeError):
            return self.bad_message("register", "Invalid UUID specified")
        self.transport.pauseProducing()

        d = self.deferToThread(self.conf.make_endpoint, self.ps.uaid, chid,
                               data.get("key"))
        d.addCallback(self.finish_register, chid)
        d.addErrback(self.trap_cancel)
        d.addErrback(self.error_register)
        return d

    def error_register(self, fail):
        """errBack handler for registering to fail"""
        self.transport.resumeProducing()
        msg = {"messageType": "register", "status": 500,
               "reason": "An unexpected server error occurred"}
        self.sendJSON(msg)
        self.log_failure(fail, extra="Failed to register")

    def finish_register(self, endpoint, chid):
        """callback for successful endpoint creation, sends register reply"""
        message = self.db.message_table(self.ps.message_month)
        d = self.deferToThread(message.register_channel, self.ps.uaid,
                               chid)
        d.addCallback(self.send_register_finish, endpoint, chid)
        # Note: No trap_cancel needed here since the deferred here is
        # returned to process_register which will trap it
        d.addErrback(self.error_overload, "register", disconnect=False)
        return d

    def send_register_finish(self, result, endpoint, chid):
        self.transport.resumeProducing()
        msg = {"messageType": "register", "channelID": chid,
               "pushEndpoint": endpoint, "status": 200}
        self.sendJSON(msg)
        self.metrics.increment("ua.command.register")
        self.ps.stats.registers += 1
        self.log.info(format="Register", channel_id=chid, endpoint=endpoint,
                      uaid_hash=self.ps.uaid_hash,
                      user_agent=self.ps.user_agent, **self.ps.raw_agent)

    def process_unregister(self, data):
        """Process an unregister message"""
        if "channelID" not in data:
            return self.bad_message("unregister", "Missing ChannelID")
        chid = data["channelID"]
        try:
            uuid.UUID(chid)
        except ValueError:
            return self.bad_message("unregister", "Invalid ChannelID")

        self.metrics.increment("ua.command.unregister")
        self.ps.stats.unregisters += 1
        event = dict(format="Unregister", channel_id=chid,
                     uaid_hash=self.ps.uaid_hash,
                     user_agent=self.ps.user_agent, **self.ps.raw_agent)
        if "code" in data:
            event["code"] = extract_code(data)
        self.log.info(**event)

        # Clear out any existing tracked messages for this channel
        self.ps.direct_updates[chid] = []
        self.ps.updates_sent[chid] = []

        # Unregister the channel
        message = self.db.message_table(self.ps.message_month)
        self.force_retry(message.unregister_channel, self.ps.uaid,
                         chid)

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

        return self._handle_webpush_ack(chid, version, code)

    def _handle_webpush_ack(self, chid, version, code):
        """Handle clearing out a webpush ack"""
        def ver_filter(notif):
            return notif.version == version

        found = filter(
            ver_filter, self.ps.direct_updates[chid]
        )  # type: List[WebPushNotification]
        if found:
            msg = found[0]
            size = len(msg.data) if msg.data else 0
            self.log.debug(format="Ack", router_key="webpush", channel_id=chid,
                           message_id=version, message_source="direct",
                           message_size=size, uaid_hash=self.ps.uaid_hash,
                           user_agent=self.ps.user_agent, code=code,
                           **self.ps.raw_agent)
            self.ps.stats.direct_acked += 1
            self.ps.direct_updates[chid].remove(msg)
            return

        found = filter(
            ver_filter, self.ps.updates_sent[chid]
        )  # type: List[WebPushNotification]
        if found:
            msg = found[0]
            size = len(msg.data) if msg.data else 0
            self.log.debug(format="Ack", router_key="webpush", channel_id=chid,
                           message_id=version, message_source="stored",
                           message_size=size, uaid_hash=self.ps.uaid_hash,
                           user_agent=self.ps.user_agent, code=code,
                           **self.ps.raw_agent)
            self.ps.stats.stored_acked += 1

            message = self.db.message_table(self.ps.message_month)
            if msg.sortkey_timestamp:
                # Is this the last un-acked message we're waiting for?
                last_unacked = sum(
                    len(sent) for sent in self.ps.updates_sent.itervalues()
                ) == 1

                if (msg.sortkey_timestamp == self.ps.current_timestamp or
                        last_unacked):
                    # If it's the last message in the batch, or last un-acked
                    # message
                    d = self.force_retry(
                        message.update_last_message_read,
                        self.ps.uaid_obj, self.ps.current_timestamp,
                    )
                    d.addBoth(self._handle_webpush_update_remove, chid, msg)
                else:
                    # It's timestamped, but not the last of this batch,
                    # so we just remove it from local tracking
                    self._handle_webpush_update_remove(None, chid, msg)
                    d = None
            else:
                # No sortkey_timestamp, so legacy/topic message, delete
                d = self.force_retry(message.delete_message, msg)
                # We don't remove the update until we know the delete ran
                # This is because we don't use range queries on dynamodb and
                # we need to make sure this notification is deleted from the
                # db before we query it again (to avoid dupes).
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

    def process_ack(self, data):
        """Process an ack message, delete notifications from storage if
        needed"""
        updates = data.get("updates")
        if not updates or not isinstance(updates, list):
            return

        self.metrics.increment("ua.command.ack")
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

        self.log.debug(format="Nack", uaid_hash=self.ps.uaid_hash,
                       user_agent=self.ps.user_agent, message_id=str(version),
                       code=code, **self.ps.raw_agent)
        mcode = code if code in NACK_CODES else 0
        self.metrics.increment(
            'ua.command.nack',
            tags=self.metrics.make_tags(code=mcode))
        self.ps.stats.nacks += 1

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
        if any(self.ps.updates_sent.values()):
            return

        # Should we check again?
        if self.ps._more_notifications:
            self.process_notifications()
        elif self.ps._check_notifications:
            # If we were told to check notifications, start over since we might
            # have missed a topic message
            self.ps.scan_timestamps = False
            self.process_notifications()

    def bad_message(self, typ, message=None, url=DEFAULT_WS_ERR):
        """Error helper for sending a 401 status back"""
        msg = {"messageType": typ, "status": 401, "more_info": url}
        if message:
            msg["reason"] = message
        self.sendJSON(msg)

    ####################################
    # Utility function for external use
    def send_notification(self, update):
        """Utility function for external use

        This function is called by the HTTP handler to deliver an incoming
        update notification from an endpoint.

        """
        chid = update["channelID"]

        # Create the notification
        notif = WebPushNotification.from_serialized(self.ps.uaid_obj, update)
        self.ps.direct_updates[chid].append(notif)
        self.emit_send_metrics(notif)
        self.sendJSON(notif.websocket_format())

    def emit_send_metrics(self, notif):
        if notif.topic:
            self.metrics.increment("ua.notification.topic")
        self.metrics.increment(
            'ua.message_data', notif.data_length,
            tags=self.metrics.make_tags(source=notif.source))


class PushServerFactory(WebSocketServerFactory):
    """PushServerProtocol factory"""

    protocol = PushServerProtocol

    def __init__(self, conf, db, agent, clients):
        # type: (AutopushConfig, DatabaseManager, Agent, Dict) -> None
        WebSocketServerFactory.__init__(self, conf.ws_url)
        self.conf = conf
        self.db = db
        self.agent = agent
        self.clients = clients
        self.setProtocolOptions(
            webStatus=False,
            openHandshakeTimeout=5,
            autoPingInterval=conf.auto_ping_interval,
            autoPingTimeout=conf.auto_ping_timeout,
            maxConnections=conf.max_connections,
            closeHandshakeTimeout=conf.close_handshake_timeout,
        )


class RouterHandler(BaseHandler):
    """Router Handler

    Handles routing a notification to a connected client from an endpoint.

    """

    def put(self, uaid):
        """HTTP Put

        Attempt delivery of a notification to a connected client.

        """
        client = self.application.clients.get(uaid)
        if not client:
            self.set_status(404, reason=None)
            self.write("Client not connected.")
            return

        if client.paused:
            self.set_status(503, reason=None)

            self.write("Client busy.")
            return

        update = json.loads(self.request.body)
        client.send_notification(update)
        self.write("Client accepted for delivery")


class NotificationHandler(BaseHandler):

    def put(self, uaid, *args):
        """HTTP Put

        Notify a connected client that it should check storage for new
        notifications.

        """
        client = self.application.clients.get(uaid)
        if not client:
            self.set_status(404, reason=None)
            self.write("Client not connected.")
            return

        if client.paused:
            # Client already busy waiting for stuff, flag for check
            client._check_notifications = True
            self.set_status(202)
            self.write("Flagged for Notification check")
            return

        # Client is online and idle, start a notification check
        client.process_notifications()
        self.metrics.increment("ua.notification_check")
        self.write("Notification check started")

    def delete(self, uaid, connected_at):
        """HTTP Delete

        Drop a connected client as the client has connected to a new node.

        """
        client = self.application.clients.get(uaid)
        if client and client.ps.connected_at == int(connected_at):
            client.sendClose()
            self.write("Terminated duplicate")


class ConnectionWSSite(Site):

    """The Websocket Site"""

    def __init__(self, conf, ws_factory):
        # type: (AutopushConfig, PushServerFactory) -> None
        self.conf = conf
        self.noisy = conf.debug

        resource = DefaultResource(WebSocketResource(ws_factory))
        resource.putChild("status", StatusResource())
        Site.__init__(self, resource)

    def ssl_cf(self):
        # type: () -> Optional[AutopushSSLContextFactory]
        """Build our SSL Factory (if configured).

        Configured from the ssl_key/cert/dh_param values.

        """
        return self.conf.ssl.cf()


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
        return json.dumps({"status": "OK", "version": __version__})
