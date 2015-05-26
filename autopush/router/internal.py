"""Interal Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores it appropriately in DynamoDB.

"""
import json
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
    return node_id + "-%s" % int(time.time()/3600)


class InternalRouter(object):
    """Implements IRouter for internal routing to an Autopush node"""
    def initialize(self, ap_settings):
        self.ap_settings = ap_settings
        self.metrics = ap_settings.metrics

    @inlineCallbacks
    def route_notification(self, notification, uaid_data):
        """Route a notification to an internal node, and store it if the node
        can't deliver immediately or is no longer a valid node"""
        # Determine if they're connected at the moment
        self.node_id = node_id = uaid_data.get("node_id")
        self.uaid = uaid_data["uaid"]
        self.uaid_data = uaid_data
        self.notification = notification

        # Node_id is present, attempt delivery.
        # - Send Notification to node
        #   - Success: Done, return 200
        #   - Error (Node busy): Jump to Save notification below
        #   - Error (Client gone, node gone/dead): Clear node entry for user
        #       - Both: Done, return 503
        if node_id:
            try:
                result = yield self._send_notification()
            except (ConnectError, UserError, ConnectionRefusedError):
                self.metrics.increment("updates.client.host_gone")
                dead_cache.put(node_key(node_id), True)
                yield deferToThread(
                    self.ap_settings.router.clear_node,
                    self.uaid_data).addErrback(self._eat_db_err)
                raise RouterException("Node was invalid", status_code=503,
                                      response_body="Retry Request")
            if result.code == 200:
                self.metrics.increment("router.broadcast.hit")
                returnValue(RouterResponse(response_body="Delivered"))

        # Node is not present or busy, store notification
        # - Save notification
        #   - Success (older version): Done, return 202
        #   - Success: Lookup client
        #       - Success (node found): Notify node of new notification
        #           - Success: Done, return 200
        #           - Error (no client): Done, return 202
        #           - Error (no node): Clear node entry
        #               - Both: Done, return 202
        #       - Success (no node): Done, return 202
        #       - Error (db error): Done, return 202
        #       - Error (no client) : Done, return 404
        #   - Error (db error): Done, return 503
        try:
            result = yield deferToThread(
                self.ap_settings.storage.save_notification,
                uaid=self.uaid,
                chid=notification.channel_id,
                version=notification.version
            )
            if result is False:
                self.metrics.increment("router.broadcast.newer_stored")
                returnValue(RouterResponse(202, "Notification Stored"))
        except ProvisionedThroughputExceededException:
            raise RouterException("Provisioned throughput error",
                                  status_code=503,
                                  response_body="Retry Request")

        try:
            self.uaid_data = yield deferToThread(
                self.ap_settings.router.get_uaid, self.uaid)
        except ProvisionedThroughputExceededException:
            self.metrics.increment("router.broadcast.miss")
            returnValue(RouterResponse(202, "Notification Stored"))
        except ItemNotFound:
            self.metrics.increment("updates.client.deleted")
            raise RouterException("User was deleted",
                                  status_code=404,
                                  response_body="Invalid UAID")

        self.node_id = self.uaid_data.get("node_id")
        if not self.node_id:
            self.metrics.increment("router.broadcast.miss")
            returnValue(RouterResponse(202, "Notification Stored"))

        try:
            result = yield self._send_notification_check()
        except (ConnectError, UserError, ConnectionRefusedError):
            self.metrics.increment("updates.client.host_gone")
            dead_cache.put(node_key(self.node_id), True)
            yield deferToThread(
                self.ap_settings.router.clear_node,
                self.uaid_data).addErrback(self._eat_db_err)
            self.metrics.increment("router.broadcast.miss")
            returnValue(RouterResponse(202, "Notification Stored"))

        if result.code == 200:
            self.metrics.increment("router.broadcast.save_hit")
            returnValue(RouterResponse("Delivered"))
        else:
            self.metrics.increment("router.broadcast.miss")
            returnValue(RouterResponse(202, "Notification Stored"))

    #############################################################
    #                    Blocking Helper Functions
    #############################################################
    def _send_notification(self):
        """Send a notification to a specific node_id"""
        payload = json.dumps([{"channelID": self.notification.channel_id,
                               "version": self.notification.version,
                               "data": self.notification.data}])
        url = self.node_id + "/push/" + self.uaid
        d = self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
            bodyProducer=FileBodyProducer(StringIO(payload)),
        )
        d.addCallback(IgnoreBody.ignore)
        return d

    def _send_notification_check(self):
        url = self.node_id + "/notif/" + self.uaid
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
