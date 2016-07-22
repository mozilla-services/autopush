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
from autopush.db import normalize_id

TTL_URL = "https://webpush-wg.github.io/webpush-protocol/#rfc.section.6.2"


class WebPushRouter(SimpleRouter):
    """SimpleRouter subclass to store individual messages appropriately"""

    def delivered_response(self, notification):
        location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                notification.version)
        return RouterResponse(status_code=201, response_body="",
                              headers={"Location": location,
                                       "TTL": notification.ttl or 0},
                              logged_status=200)

    def stored_response(self, notification):
        location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                notification.version)
        return RouterResponse(status_code=201, response_body="",
                              headers={"Location": location,
                                       "TTL": notification.ttl},
                              logged_status=202)

    def _crypto_headers(self, notification):
        """Creates a dict of the crypto headers for this request."""
        headers = notification.headers
        data = dict(
            encoding=headers["content-encoding"],
            encryption=headers["encryption"],
        )
        # AWS cannot store empty strings, so we only add these keys if
        # they're present to avoid empty strings.
        for name in ["encryption-key", "crypto-key"]:
            if name in headers:
                # NOTE: The client code expects all header keys to be lower
                # case and s/-/_/.
                data[name.lower().replace("-", "_")] = headers[name]
        return data

    @inlineCallbacks
    def preflight_check(self, uaid, channel_id):
        """Verifies this routing call can be done successfully"""
        # Locate the user agent's message table
        record = yield deferToThread(self.ap_settings.router.get_uaid, uaid)

        if 'current_month' not in record:
            self.log.info("Record missing 'current_month' {record}",
                          record=json.dumps(record))
            raise RouterException("No such subscription", status_code=410,
                                  log_exception=False, errno=106)

        month_table = record["current_month"]
        if month_table not in self.ap_settings.message_tables:
            self.log.info("'current_month' out of scope: {record}",
                          records=json.dumps(record))
            yield deferToThread(self.ap_settings.router.drop_user, uaid)
            raise RouterException("No such subscription", status_code=410,
                                  log_exception=False, errno=106)
        exists, chans = yield deferToThread(
            self.ap_settings.message_tables[month_table].all_channels,
            uaid=uaid)

        if (not exists or channel_id.lower() not
                in map(lambda x: normalize_id(x), chans)):
            self.log.info("Unknown subscription: {channel_id}",
                          channelid=channel_id)
            raise RouterException("No such subscription", status_code=410,
                                  log_exception=False, errno=106)
        returnValue(month_table)

    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id

        This version of the overriden method includes the necessary crypto
        headers for the notification.

        """
        # Firefox currently requires channelIDs to be '-' formatted.
        payload = {"channelID": normalize_id(notification.channel_id),
                   "version": notification.version,
                   "ttl": notification.ttl or 0,
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
        if notification.ttl is None:
            # Note that this URL is temporary, as well as this warning as
            # we will 400 all missing TTL's eventually
            raise RouterException(
                "Missing TTL Header",
                response_body="Missing TTL Header, see: %s" % TTL_URL,
                status_code=400,
                errno=111,
                log_exception=False,
            )
        if notification.ttl == 0:
            location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                    notification.version)
            raise RouterException("Finished Routing", status_code=201,
                                  log_exception=False,
                                  headers={"TTL": str(notification.ttl),
                                           "Location": location},
                                  logged_status=204)
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

    def amend_msg(self, msg, router_data=None):
        return msg
