"""WebPush Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores each individual message, along with its data, in a Message
table for retrieval by the client.

"""
import json
import time
from StringIO import StringIO

from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
)
from twisted.internet.threads import deferToThread
from twisted.web.client import FileBodyProducer

from autopush.protocol import IgnoreBody
from autopush.router.interface import RouterException, RouterResponse
from autopush.router.simple import SimpleRouter


class WebPushRouter(SimpleRouter):
    """SimpleRouter subclass to store individual messages appropriately"""

    def delivered_response(self, notification):
        location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                notification.version)
        return RouterResponse(status_code=201, response_body="",
                              headers={"Location": location,
                                       "TTL": notification.ttl})
    stored_response = delivered_response

    def _crypto_headers(self, notification):
        """Creates a dict of the crypto headers for this request."""
        headers = notification.headers
        data = dict(
            encoding=headers["content-encoding"],
            encryption=headers["encryption"],
        )
        # AWS cannot store empty strings, so we only add the encryption-key and
        # crypto-key if present to avoid empty strings.
        if "encryption-key" in headers:
            data["encryption_key"] = headers["encryption-key"]
        if "crypto-key" in headers:
            data["crypto_key"] = headers["crypto-key"]
        return data

    @inlineCallbacks
    def preflight_check(self, uaid, channel_id):
        """Verifies this routing call can be done successfully"""
        # Locate the user agent's message table
        record = yield deferToThread(self.ap_settings.router.get_uaid, uaid)

        if 'current_month' not in record:
            raise RouterException("No such subscription", status_code=404,
                                  log_exception=False, errno=106)

        month_table = record["current_month"]
        exists, chans = yield deferToThread(
            self.ap_settings.message_tables[month_table].all_channels,
            uaid=uaid)

        if not exists or channel_id not in chans:
            raise RouterException("No such subscription", status_code=404,
                                  log_exception=False, errno=106)
        returnValue(month_table)

    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id

        This version of the overriden method includes the necessary crypto
        headers for the notification.

        """
        payload = {"channelID": notification.channel_id,
                   "version": notification.version,
                   "ttl": notification.ttl,
                   "timestamp": int(time.time()),
                   }
        if notification.data:
            payload["headers"] = self._crypto_headers(notification)
            payload["data"] = notification.data
        url = node_id + "/push/" + uaid
        d = self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
            bodyProducer=FileBodyProducer(StringIO(json.dumps(payload))),
        )
        d.addCallback(IgnoreBody.ignore)
        return d

    def _save_notification(self, uaid, notification, month_table):
        """Saves a notification, returns a deferred.

        This version of the overridden method saves each individual message
        to the message table along with relevant request headers if
        available.

        """
        if notification.ttl == 0:
            raise RouterException("Finished Routing", status_code=201,
                                  log_exception=False,
                                  headers={"TTL": str(notification.ttl)})
        headers = None
        if notification.data:
            headers = self._crypto_headers(notification)
        return deferToThread(
            self.ap_settings.message_tables[month_table].store_message,
            uaid=uaid,
            channel_id=notification.channel_id,
            data=notification.data,
            headers=headers,
            message_id=notification.version,
            ttl=notification.ttl,
            timestamp=int(time.time()),
        )

    def amend_msg(self, msg):
        return msg

    def check_token(self, token):
        return (True, token)
