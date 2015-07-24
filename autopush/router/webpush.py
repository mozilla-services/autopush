"""WebPush Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores each individual message, along with its data, in a Message
table for retrieval by the client.

"""
import json
from StringIO import StringIO

from twisted.internet.threads import deferToThread
from twisted.web.client import FileBodyProducer

from autopush.protocol import IgnoreBody
from autopush.router.simple import SimpleRouter


class WebPushRouter(SimpleRouter):
    """SimpleRouter subclass to store individual messages appropriately"""
    def _crypto_headers(self):
        """Creates a dict of the crypto headers for this request."""
        return dict(
            encoding=self.request.headers["content-encoding"],
            encryption=self.request.headers["encryption"],
            encryption_key=self.request.headers.get("encryption-key", ""),
        )

    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id

        This version of the overriden method includes the necessary crypto
        headers for the notification.

        """
        payload = json.dumps({"channelID": notification.channel_id,
                              "version": notification.version,
                              "data": notification.data,
                              "headers": self._crypto_headers(),
                              })
        url = node_id + "/push/" + uaid
        d = self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
            bodyProducer=FileBodyProducer(StringIO(payload)),
        )
        d.addCallback(IgnoreBody.ignore)
        return d

    def _save_notification(self, uaid, notification):
        """Saves a notification, returns a deferred.

        This version of the overridden method saves each individual message
        to the message table along with relevant request headers if
        available.

        """
        return deferToThread(
            self.ap_settings.message_table.store_message,
            uaid=uaid,
            channel_id=notification.channel_id,
            data=notification.data,
            headers=self._crypto_headers(),
            timestamp=notification.timestamp,
        )
