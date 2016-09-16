"""Simple(Push) Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores it appropriately in DynamoDB for SimplePush style version
based channel ID's (only newest version is stored, no data stored).

"""
import json
import requests
from urllib import urlencode
from StringIO import StringIO

from boto.dynamodb2.exceptions import (
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from twisted.internet.threads import deferToThread
from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
)
from twisted.internet.error import (
    ConnectError,
    ConnectionClosed,
    ConnectionRefusedError,
)
from twisted.logger import Logger
from twisted.web._newclient import ResponseFailed
from twisted.web.client import FileBodyProducer

from autopush.protocol import IgnoreBody
from autopush.router.interface import (
    RouterException,
    RouterResponse,
)


class SimpleRouter(object):
    """Implements :class:`autopush.router.interface.IRouter` for internal
    routing to an Autopush node
    """
    log = Logger()

    def __init__(self, ap_settings, router_conf):
        """Create a new SimpleRouter"""
        self.ap_settings = ap_settings
        self.metrics = ap_settings.metrics
        self.conf = router_conf
        self.waker = None

    def register(self, uaid, *args, **kwargs):
        """Return no additional routing data"""
        return {}

    def amend_msg(self, msg, router_data=None):
        return msg

    def preflight_check(self, uaid_data, channel_id):
        """Verifies this routing call can be done successfully"""
        return True

    def stored_response(self, notification):
        return RouterResponse(202, "Notification Stored")

    def delivered_response(self, notification):
        return RouterResponse(200, "Delivered")

    @inlineCallbacks
    def route_notification(self, notification, uaid_data):
        """Route a notification to an internal node, and store it if the node
        can't deliver immediately or is no longer a valid node
        """
        # Determine if they're connected at the moment
        node_id = uaid_data.get("node_id")
        uaid = uaid_data["uaid"]
        self.udp = uaid_data.get("udp")
        router = self.ap_settings.router

        # Preflight check, hook used by webpush to verify channel id, extra
        # stores any additional data to pass to storing the message
        extra = yield self.preflight_check(uaid_data, notification.channel_id)

        # Node_id is present, attempt delivery.
        # - Send Notification to node
        #   - Success: Done, return 200
        #   - Error (Node busy): Jump to Save notification below
        #   - Error (Client gone, node gone/dead): Clear node entry for user
        #       - Both: Done, return 503
        if node_id:
            result = None
            try:
                result = yield self._send_notification(uaid, node_id,
                                                       notification)
            except (ConnectError, ConnectionClosed, ResponseFailed) as exc:
                self.metrics.increment("updates.client.host_gone")
                yield deferToThread(router.clear_node,
                                    uaid_data).addErrback(self._eat_db_err)
                if isinstance(exc, ConnectionRefusedError):
                    # Occurs if an IP record is now used by some other node
                    # in AWS.
                    self.log.debug("Could not route message: {exc}", exc=exc)
            if result and result.code == 200:
                self.metrics.increment("router.broadcast.hit")
                returnValue(self.delivered_response(notification))

        # Save notification, node is not present or busy
        # - Save notification
        #   - Success (older version): Done, return 202
        #   - Error (db error): Done, return 503
        try:
            result = yield self._save_notification(uaid, notification, extra)
            if result is False:
                self.metrics.increment("router.broadcast.miss")
                returnValue(self.stored_response(notification))
        except ProvisionedThroughputExceededException:
            raise RouterException("Provisioned throughput error",
                                  status_code=503,
                                  response_body="Retry Request",
                                  errno=201)

        # - Lookup client
        #   - Success (node found): Notify node of new notification
        #     - Success: Done, return 200
        #     - Error (no client): Done, return 202
        #     - Error (no node): Clear node entry
        #       - Both: Done, return 202
        #   - Success (no node): Done, return 202
        #   - Error (db error): Done, return 202
        #   - Error (no client) : Done, return 404
        try:
            uaid_data = yield deferToThread(router.get_uaid, uaid)
        except ProvisionedThroughputExceededException:
            self.metrics.increment("router.broadcast.miss")
            returnValue(self.stored_response(notification))
        except ItemNotFound:
            self.metrics.increment("updates.client.deleted")
            raise RouterException("User was deleted",
                                  status_code=410,
                                  response_body="Invalid UAID",
                                  log_exception=False,
                                  errno=105)

        # Verify there's a node_id in here, if not we're done
        node_id = uaid_data.get("node_id")
        if not node_id:
            self.metrics.increment("router.broadcast.miss")
            returnValue(self.stored_response(notification))
        try:
            result = yield self._send_notification_check(uaid, node_id)
        except (ConnectError, ConnectionClosed, ResponseFailed) as exc:
            self.metrics.increment("updates.client.host_gone")
            if isinstance(exc, ConnectionRefusedError):
                self.log.debug("Could not route message: {exc}", exc=exc)
            yield deferToThread(
                router.clear_node,
                uaid_data).addErrback(self._eat_db_err)
            self.metrics.increment("router.broadcast.miss")
            returnValue(self.stored_response(notification))

        if result.code == 200:
            self.metrics.increment("router.broadcast.save_hit")
            returnValue(self.delivered_response(notification))
        else:
            self.metrics.increment("router.broadcast.miss")
            ret_val = self.stored_response(notification)
            if self.udp is not None and "server" in self.conf:
                # Attempt to send off the UDP wake request.
                try:
                    yield deferToThread(
                        requests.post(
                            self.conf["server"],
                            data=urlencode(self.udp["data"]),
                            cert=self.conf.get("cert"),
                            timeout=self.conf.get("server_timeout", 3)))
                except Exception as exc:
                    self.log.debug("Could not send UDP wake request: {exc}",
                                   exc=exc)
            returnValue(ret_val)

    #############################################################
    #                    Blocking Helper Functions
    #############################################################
    def _save_notification(self, uaid, notification, extra):
        """Saves a notification, returns a deferred.

        This function is split out for the Webpush-style individual
        message storage to subclass and override.

        """
        return deferToThread(self.ap_settings.storage.save_notification,
                             uaid=uaid, chid=notification.channel_id,
                             version=notification.version)

    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id"""
        payload = json.dumps({"channelID": notification.channel_id,
                              "version": notification.version,
                              "data": notification.data})
        url = node_id + "/push/" + uaid
        d = self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
            bodyProducer=FileBodyProducer(StringIO(payload)),
        )
        d.addCallback(IgnoreBody.ignore)
        return d

    def _send_notification_check(self, uaid, node_id):
        """Send a command to the node to check for notifications"""
        url = node_id + "/notif/" + uaid
        return self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
        ).addCallback(IgnoreBody.ignore)

    #############################################################
    #                    Error Callbacks
    #############################################################
    def _eat_db_err(self, fail):
        """errBack for ignoring provisioned throughput errors"""
        fail.trap(ProvisionedThroughputExceededException)
