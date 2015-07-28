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
from autopush.router.interface import RouterResponse
from autopush.router.simple import SimpleRouter


class WebPushRouter(SimpleRouter):
    """SimpleRouter subclass to store individual messages appropriately"""

    @property
    def delivered_response(self):
        return RouterResponse(
            status_code=201,
            response_body="",
            headers={"Location":
                     self.ap_settings.endpoint_url + '/m/' + self.message_id}
        )
    stored_response = delivered_response

    def _crypto_headers(self, notification):
        """Creates a dict of the crypto headers for this request."""
        headers = notification.headers
        data = dict(
            encoding=headers["content-encoding"],
            encryption=headers["encryption"],
        )
        # AWS cannot store empty strings, so we only add the encryption-key if
        # its present to avoid empty strings.
        if "encryption-key" in headers:
            data["encryption_key"] = headers["encryption-key"]
        return data

    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id

        This version of the overriden method includes the necessary crypto
        headers for the notification.

        """
        payload = json.dumps({"channelID": notification.channel_id,
                              "version": notification.version,
                              "data": notification.data,
                              "headers": self._crypto_headers(notification),
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
            self.ap_settings.message.store_message,
            uaid=uaid,
            channel_id=notification.channel_id,
            data=notification.data,
            headers=self._crypto_headers(notification),
            message_id=notification.version,
        )
