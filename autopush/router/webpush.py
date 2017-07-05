"""WebPush Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores each individual message, along with its data, in a Message
table for retrieval by the client.

"""
import json
import time
from StringIO import StringIO

from twisted.internet.threads import deferToThread
from twisted.web.client import FileBodyProducer

from autopush.exceptions import RouterException
from autopush.metrics import make_tags
from autopush.protocol import IgnoreBody
from autopush.router.interface import RouterResponse
from autopush.router.simple import SimpleRouter

TTL_URL = "https://webpush-wg.github.io/webpush-protocol/#rfc.section.6.2"


class WebPushRouter(SimpleRouter):
    """SimpleRouter subclass to store individual messages appropriately"""

    def delivered_response(self, notification):
        self.metrics.gauge("notification.message_data",
                           notification.data_length,
                           tags=make_tags(destination='Stored'))
        location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                notification.location)
        return RouterResponse(status_code=201, response_body="",
                              headers={"Location": location,
                                       "TTL": notification.ttl or 0},
                              logged_status=200)

    def stored_response(self, notification):
        self.metrics.gauge("notification.message_data",
                           notification.data_length,
                           tags=make_tags(destination='Direct'))
        location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                notification.location)
        return RouterResponse(status_code=201, response_body="",
                              headers={"Location": location,
                                       "TTL": notification.ttl},
                              logged_status=202)

    def _send_notification(self, uaid, node_id, notification):
        """Send a notification to a specific node_id

        This version of the overriden method includes the necessary crypto
        headers for the notification.

        :type notification: autopush.utils.WebPushNotification

        """
        payload = notification.serialize()
        payload["timestamp"] = int(time.time())
        url = node_id + "/push/" + uaid
        request = self.agent.request(
            "PUT",
            url.encode("utf8"),
            bodyProducer=FileBodyProducer(StringIO(json.dumps(payload))),
        )
        request.addCallback(IgnoreBody.ignore)
        return request

    def _save_notification(self, uaid_data, notification):
        """Saves a notification, returns a deferred.

        This version of the overridden method saves each individual message
        to the message table along with relevant request headers if
        available.

        :type uaid_data: dict

        """
        month_table = uaid_data["current_month"]
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
        return deferToThread(
            self.db.message_tables[month_table].store_message,
            notification=notification,
        )
