"""Simple(Push) Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores it appropriately in DynamoDB for SimplePush style version
based channel ID's (only newest version is stored, no data stored).

"""
import json
from StringIO import StringIO
from twisted.internet.threads import deferToThread
from twisted.logger import Logger
from twisted.web.client import FileBodyProducer

from autopush.metrics import make_tags
from autopush.protocol import IgnoreBody
from autopush.router.interface import RouterResponse
from autopush.router.webpush import WebPushRouter


class SimpleRouter(WebPushRouter):
    """Implements :class:`autopush.router.interface.IRouter` for internal
    routing to an Autopush node
    """
    log = Logger()

    def stored_response(self, notification):
        self.metrics.increment("notification.message_data",
                               notification.data_length,
                               tags=make_tags(destination='Stored'))
        return RouterResponse(202, "Notification Stored")

    def delivered_response(self, notification):
        self.metrics.increment("notification.message_data",
                               notification.data_length,
                               tags=make_tags(destination='Direct'))
        return RouterResponse(200, "Delivered")

    #############################################################
    #                    Blocking Helper Functions
    #############################################################
    def _save_notification(self, uaid_data, notification):
        """Saves a notification, returns a deferred.

        This function is split out for the Webpush-style individual
        message storage to subclass and override.

        """
        uaid = uaid_data["uaid"]
        return deferToThread(self.db.storage.save_notification,
                             uaid=uaid, chid=notification.channel_id,
                             version=notification.version)

    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id"""
        payload = json.dumps({"channelID": notification.channel_id,
                              "version": notification.version,
                              "data": notification.data})
        url = node_id + "/push/" + uaid
        d = self.agent.request(
            "PUT",
            url.encode("utf8"),
            bodyProducer=FileBodyProducer(StringIO(payload)),
        )
        d.addCallback(IgnoreBody.ignore)
        return d
