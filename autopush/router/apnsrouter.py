"""APNS Router"""
import uuid

from twisted.logger import Logger
from twisted.internet.threads import deferToThread

from autopush.exceptions import RouterException
from autopush.router.apns2 import (
    APNSClient,
    APNS_MAX_CONNECTIONS,
)
from autopush.router.interface import RouterResponse


# https://github.com/djacobs/PyAPNs
class APNSRouter(object):
    """APNS Router Implementation"""
    log = Logger()
    apns = None

    def _connect(self, rel_channel):
        """Connect to APNS

        :param rel_channel: Release channel name (e.g. Firefox. FirefoxBeta,..)
        :type rel_channel: str

        :returns: APNs to be stored under the proper release channel name.
        :rtype: apns.APNs

        """
        default_topic = "com.mozilla.org." + rel_channel
        cert_info = self._config[rel_channel]
        return APNSClient(
            cert_file=cert_info.get("cert"),
            key_file=cert_info.get("key"),
            use_sandbox=cert_info.get("sandbox", False),
            max_connections=cert_info.get("max_connections",
                                          APNS_MAX_CONNECTIONS),
            topic=cert_info.get("topic", default_topic),
            logger=self.log,
            metrics=self.ap_settings.metrics)

    def __init__(self, ap_settings, router_conf):
        """Create a new APNS router and connect to APNS"""
        self.ap_settings = ap_settings
        self._base_tags = []
        self.apns = dict()
        self._config = router_conf
        for rel_channel in self._config:
            self.apns[rel_channel] = self._connect(rel_channel)
        self.ap_settings = ap_settings
        self.log.debug("Starting APNS router...")

    def register(self, uaid, router_data, app_id, *args, **kwargs):
        """Register an endpoint for APNS, on the `app_id` release channel.

        This will validate that an APNs instance token is in the
        ``router_data``,

        :param uaid: User Agent Identifier
        :type uaid: str
        :param router_data: Dict containing router specific configuration info
        :type router_data: dict
        :param app_id: The release channel identifier for cert info lookup
        :type app_id: str

        :returns: a modified router_data for the user agent record.
        :rtype: dict


        """
        if app_id not in self.apns:
            raise RouterException("Unknown release channel specified",
                                  status_code=400,
                                  response_body="Unknown release channel")
        if not router_data.get("token"):
            raise RouterException("No token registered", status_code=500,
                                  response_body="No token registered")
        router_data["rel_channel"] = app_id
        return router_data

    def amend_msg(self, msg, router_data=None):
        """This function is stubbed out for this router"""
        return msg

    def route_notification(self, notification, uaid_data):
        """Start the APNS notification routing, returns a deferred

        :param notification: Notification data to send
        :type notification: autopush.endpoint.Notification
        :param uaid_data: User Agent specific data
        :type uaid_data: dict

        """
        router_data = uaid_data["router_data"]
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, router_data)

    def _route(self, notification, router_data):
        """Blocking APNS call to route the notification

        :param notification: Notification data to send
        :type notification: dict
        :param router_data: Pre-initialized data for this connection
        :type router_data: dict

        """
        router_token = router_data["token"]
        rel_channel = router_data["rel_channel"]
        config = self._config[rel_channel]
        apns_client = self.apns[rel_channel]
        payload = {
            "chid": str(notification.channel_id),
            "ver": notification.version,
        }
        if notification.data:
            payload["body"] = notification.data
            payload["con"] = notification.headers["content-encoding"]
            payload["enc"] = notification.headers["encryption"]

            if "crypto-key" in notification.headers:
                payload["cryptokey"] = notification.headers["crypto-key"]
            elif "encryption-key" in notification.headers:
                payload["enckey"] = notification.headers["encryption-key"]
            payload['aps'] = dict(
                alert=router_data.get("title", config.get('default_title',
                                                          'Mozilla Push')),
                content_available=1)
        apns_id = str(uuid.uuid4()).lower()

        apns_client.send(router_token=router_token, payload=payload,
                         apns_id=apns_id)
        location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                notification.version)
        self.ap_settings.metrics.increment(
            "updates.client.bridge.apns.%s.sent" %
            router_data["rel_channel"],
            self._base_tags)
        return RouterResponse(status_code=201, response_body="",
                              headers={"TTL": notification.ttl,
                                       "Location": location},
                              logged_status=200)
