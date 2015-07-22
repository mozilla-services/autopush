"""WebPush Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores each individual message, along with its data, in a Message
table for retrieval by the client.

"""
from twisted.internet.threads import deferToThread

from autopush.router.simple import SimpleRouter


class WebPushRouter(SimpleRouter):
    """SimpleRouter subclass to store individual messages appropriately"""
    def _save_notification(self, uaid, notification):
        """Saves a notification, returns a deferred.

        This version of the overridden method saves each individual message
        to the message table along with relevant request headers if
        available.

        """
        request_headers = dict(
            encoding=self.request.headers["content-encoding"],
            encryption=self.request.headers["encryption"],
            encryption_key=self.request.headers.get("encryption-key", ""),
        )
        return deferToThread(
            self.ap_settings.message_table.store_message,
            uaid=uaid,
            channel_id=notification.channel_id,
            data=notification.data,
            headers=request_headers,
            timestamp=notification.timestamp,
        )
