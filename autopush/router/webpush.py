"""WebPush Style Autopush Router

This router handles notifications that should be dispatched to an Autopush
node, or stores each individual message, along with its data, in a Message
table for retrieval by the client.

"""
import json
import time
from StringIO import StringIO
from typing import Any  # noqa

from botocore.exceptions import ClientError
from twisted.internet.threads import deferToThread
from twisted.web.client import FileBodyProducer
from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
    CancelledError,
)
from twisted.internet.error import (
    ConnectError,
    ConnectionClosed,
    ConnectionRefusedError,
)
from twisted.logger import Logger
from twisted.web._newclient import ResponseFailed
from twisted.web.http import PotentialDataLoss

from autopush.exceptions import ItemNotFound, RouterException
from autopush.metrics import make_tags
from autopush.protocol import IgnoreBody
from autopush.router.interface import RouterResponse
from autopush.types import JSONDict  # noqa

TTL_URL = "https://webpush-wg.github.io/webpush-protocol/#rfc.section.6.2"


class WebPushRouter(object):
    """Implements :class: `autopush.router.interface.IRouter` for internal
    routing to an autopush node

    """
    log = Logger()

    def __init__(self, conf, router_conf, db, agent):
        """Create a new Router"""
        self.conf = conf
        self.router_conf = router_conf
        self.db = db
        self.agent = agent

    @property
    def metrics(self):
        return self.db.metrics

    def register(self, uaid, router_data, app_id, *args, **kwargs):
        # type: (str, JSONDict, str, *Any, **Any) -> None
        """No additional routing data"""

    def amend_endpoint_response(self, response, router_data):
        # type: (JSONDict, JSONDict) -> None
        """Stubbed out for this router"""

    @inlineCallbacks
    def route_notification(self, notification, uaid_data):
        """Route a notification to an internal node, and store it if the node
        can't deliver immediately or is no longer a valid node
        """
        # Determine if they're connected at the moment
        node_id = uaid_data.get("node_id")
        uaid = uaid_data["uaid"]
        router = self.db.router

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
            except (ConnectError, ConnectionClosed, ResponseFailed,
                    CancelledError, PotentialDataLoss) as exc:
                self.metrics.increment("updates.client.host_gone")
                yield deferToThread(router.clear_node,
                                    uaid_data).addErrback(self._eat_db_err)
                if isinstance(exc, ConnectionRefusedError):
                    # Occurs if an IP record is now used by some other node
                    # in AWS or if the connection timesout.
                    self.log.debug("Could not route message: {exc}", exc=exc)
            if result and result.code == 200:
                returnValue(self.delivered_response(notification))

        # Save notification, node is not present or busy
        # - Save notification
        #   - Success (older version): Done, return 202
        #   - Error (db error): Done, return 503
        try:
            yield self._save_notification(uaid_data, notification)
        except ClientError as e:
            log_exception = (e.response["Error"]["Code"] !=
                             "ProvisionedThroughputExceededException")
            raise RouterException("Error saving to database",
                                  status_code=503,
                                  response_body="Retry Request",
                                  log_exception=log_exception,
                                  errno=201)

        # - Lookup client again to get latest node state after save.
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
        except ClientError:
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
            returnValue(self.stored_response(notification))

        if result.code == 200:
            returnValue(self.delivered_response(notification))
        else:
            ret_val = self.stored_response(notification)
            returnValue(ret_val)

    def delivered_response(self, notification):
        self.metrics.increment("notification.message_data",
                               notification.data_length,
                               tags=make_tags(destination='Direct'))
        location = "%s/m/%s" % (self.conf.endpoint_url, notification.location)
        return RouterResponse(status_code=201, response_body="",
                              headers={"Location": location,
                                       "TTL": notification.ttl or 0},
                              logged_status=200)

    def stored_response(self, notification):
        self.metrics.increment("notification.message_data",
                               notification.data_length,
                               tags=make_tags(destination='Stored'))
        location = "%s/m/%s" % (self.conf.endpoint_url, notification.location)
        return RouterResponse(status_code=201, response_body="",
                              headers={"Location": location,
                                       "TTL": notification.ttl},
                              logged_status=202)

    #############################################################
    #                    Blocking Helper Functions
    #############################################################

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

    def _send_notification_check(self, uaid, node_id):
        """Send a command to the node to check for notifications"""
        url = node_id + "/notif/" + uaid
        return self.agent.request(
            "PUT",
            url.encode("utf8"),
        ).addCallback(IgnoreBody.ignore)

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
            location = "%s/m/%s" % (self.conf.endpoint_url,
                                    notification.version)
            raise RouterException("Finished Routing", status_code=201,
                                  log_exception=False,
                                  headers={"TTL": str(notification.ttl),
                                           "Location": location},
                                  logged_status=204)
        return deferToThread(
            self.db.message_table(month_table).store_message,
            notification=notification,
        )

    #############################################################
    #                    Error Callbacks
    #############################################################
    def _eat_db_err(self, fail):
        """errBack for ignoring provisioned throughput errors"""
        fail.trap(ClientError)
