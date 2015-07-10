"""Simple(Push) Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores it appropriately in DynamoDB for SimplePush style version
based channel ID's (only newest version is stored, no data stored).

"""
import json
import requests
import time
from StringIO import StringIO

from boto.dynamodb2.exceptions import (
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from repoze.lru import LRUCache
from twisted.internet.threads import deferToThread
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.error import (
    ConnectError,
    ConnectionRefusedError,
    UserError
)
from twisted.web.client import FileBodyProducer

from autopush.protocol import IgnoreBody
from autopush.router.interface import (
    RouterException,
    RouterResponse,
)


dead_cache = LRUCache(150)


def node_key(node_id):
    """Generate a node key for the dead node cache"""
    return node_id + "-%s" % int(time.time() / 3600)


class SimpleRouter(object):
    """Implements :class:`autopush.router.interface.IRouter` for internal
    routing to an Autopush node"""
    def __init__(self, ap_settings, router_conf):
        """Create a new SimpleRouter"""
        self.ap_settings = ap_settings
        self.metrics = ap_settings.metrics
        self.conf = router_conf

    def register(self, uaid, connect):
        """Return no additional routing data"""
        return {}

    @inlineCallbacks
    def route_notification(self, notification, uaid_data):
        """Route a notification to an internal node, and store it if the node
        can't deliver immediately or is no longer a valid node"""
        # Determine if they're connected at the moment
        node_id = uaid_data.get("node_id")
        uaid = uaid_data["uaid"]
        self.udp = None
        try:
            self.udp = json.loads(uaid_data["udp"])
        except (TypeError, KeyError):
            # No UDP info found, ignoring.
            pass
        router, storage = self.ap_settings.router, self.ap_settings.storage

        # Node_id is present, attempt delivery.
        # - Send Notification to node
        #   - Success: Done, return 200
        #   - Error (Node busy): Jump to Save notification below
        #   - Error (Client gone, node gone/dead): Clear node entry for user
        #       - Both: Done, return 503
        if node_id:
            try:
                result = yield self._send_notification(uaid, node_id,
                                                       notification)
            except (ConnectError, UserError, ConnectionRefusedError):
                self.metrics.increment("updates.client.host_gone")
                dead_cache.put(node_key(node_id), True)
                yield deferToThread(router.clear_node,
                                    uaid_data).addErrback(self._eat_db_err)
                raise RouterException("Node was invalid", status_code=503,
                                      response_body="Retry Request")
            if result.code == 200:
                self.metrics.increment("router.broadcast.hit")
                returnValue(RouterResponse(response_body="Delivered"))

        # Save notification, node is not present or busy
        # - Save notification
        #   - Success (older version): Done, return 202
        #   - Error (db error): Done, return 503
        try:
            result = yield deferToThread(storage.save_notification, uaid=uaid,
                                         chid=notification.channel_id,
                                         version=notification.version)
            if result is False:
                self.metrics.increment("router.broadcast.miss")
                returnValue(RouterResponse(202, "Notification Stored"))
        except ProvisionedThroughputExceededException:
            raise RouterException("Provisioned throughput error",
                                  status_code=503,
                                  response_body="Retry Request")

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
            returnValue(RouterResponse(202, "Notification Stored"))
        except ItemNotFound:
            self.metrics.increment("updates.client.deleted")
            raise RouterException("User was deleted",
                                  status_code=404,
                                  response_body="Invalid UAID")

        # Verify there's a node_id in here, if not we're done
        node_id = uaid_data.get("node_id")
        if not node_id:
            self.metrics.increment("router.broadcast.miss")
            returnValue(RouterResponse(202, "Notification Stored"))
        try:
            result = yield self._send_notification_check(uaid, node_id)
        except (ConnectError, UserError, ConnectionRefusedError):
            self.metrics.increment("updates.client.host_gone")
            dead_cache.put(node_key(node_id), True)
            yield deferToThread(
                router.clear_node,
                uaid_data).addErrback(self._eat_db_err)
            self.metrics.increment("router.broadcast.miss")
            returnValue(RouterResponse(202, "Notification Stored"))

        if result.code == 200:
            self.metrics.increment("router.broadcast.save_hit")
            returnValue(RouterResponse(response_body="Delivered"))
        else:
            self.metrics.increment("router.broadcast.miss")
            if self.udp is not None:
                yield deferToThread(self._send_udp_wake,
                                    self.udp)
            returnValue(RouterResponse(202, "Notification Stored"))

    def _send_udp_wake(self, udp_info):
        host = udp_info.get("wakeup_host").get("ip")
        port = udp_info.get("wakeup_host").get("port")
        data = json.dumps(udp_info.get("mobilenetwork", {}))
        if port is not None:
            host = "%s:%d" % (host, port)
        response = requests.post(
            "https://" + host,
            data=data,
            cert=self.conf.get("cert"))
        if response.status_code < 200 or response.status_code >= 300:
            raise RouterException("Could not send UDP Wakeup",
                                  status_code=500,
                                  response_body="Could not send UDP Wakeup")

    ###########################################################
    #                    Blocking Helper Functions
    #############################################################
    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id"""
        payload = json.dumps([{"channelID": notification.channel_id,
                               "version": notification.version,
                               "data": notification.data}])
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
