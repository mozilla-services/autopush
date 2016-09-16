"""APNS Router"""
import time
import uuid

import apns
from twisted.logger import Logger
from twisted.internet.threads import deferToThread
from autopush.router.interface import RouterException, RouterResponse


# https://github.com/djacobs/PyAPNs
class APNSRouter(object):
    """APNS Router Implementation"""
    log = Logger()
    apns = None
    messages = {}
    errors = {0: 'No error',
              1: 'Processing error',
              2: 'Missing device token',
              3: 'Missing topic',
              4: 'Missing payload',
              5: 'Invalid token size',
              6: 'Invalid topic size',
              7: 'Invalid payload size',
              8: 'Invalid token',
              10: 'Shutdown',
              255: 'Unknown',
              }

    def _connect(self, cert_info):
        """Connect to APNS

        :param cert_info: APNS certificate configuration info
        :type cert_info: dict

        :returns: APNs to be stored under the proper release channel name.
        :rtype: apns.APNs

        """
        # Do I still need to call this in _error?
        return apns.APNs(
            use_sandbox=cert_info.get("sandbox", False),
            cert_file=cert_info.get("cert"),
            key_file=cert_info.get("key"),
            enhanced=True)

    def __init__(self, ap_settings, router_conf):
        """Create a new APNS router and connect to APNS"""
        self.ap_settings = ap_settings
        self._base_tags = []
        self.apns = dict()
        self.messages = dict()
        self._config = router_conf
        self._max_messages = self._config.pop('max_messages', 100)
        for rel_channel in self._config:
            self.apns[rel_channel] = self._connect(self._config[rel_channel])
            self.apns[rel_channel].gateway_server.register_response_listener(
                self._error)
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
        :type notification: dict
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
        if len(self.messages) >= self._max_messages:
            raise RouterException("Too many messages in pending queue",
                                  status_code=503,
                                  response_body="Pending buffer full",
                                  )
        apns_client = self.apns[rel_channel]
        custom = {
            "chid": notification.channel_id,
            "ver": notification.version,
        }
        if notification.data:
            custom["body"] = notification.data
            custom["con"] = notification.headers["content-encoding"]
            custom["enc"] = notification.headers["encryption"]

            if "crypto-key" in notification.headers:
                custom["cryptokey"] = notification.headers["crypto-key"]
            elif "encryption-key" in notification.headers:
                custom["enckey"] = notification.headers["encryption-key"]

        payload = apns.Payload(
            alert=router_data.get("title", config.get('default_title',
                                                      'Mozilla Push')),
            content_available=1,
            custom=custom)
        now = time.time()

        # "apns-id"
        msg_id = str(uuid.uuid4())
        self.messages[msg_id] = {
            "time_sent": now,
            "rel_channel": router_data["rel_channel"],
            "router_token": router_token,
            "payload": payload}

        apns_client.gateway_server.send_notification(router_token, payload,
                                                     msg_id)
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

    def _cleanup(self):
        """clean up pending, but expired messages.

        APNs may not always respond with a status code, this will clean out
        pending retryable messages.

        """
        for msg_id in self.messages.keys():
            message = self.messages[msg_id]
            expry = self._config[message['rel_channel']].get("expry", 10)
            if message["time_sent"] < time.time() - expry:
                try:
                    del self.messages[msg_id]
                except KeyError:  # pragma nocover
                    pass

    def _error(self, err):
        """Error handler"""
        if err['status'] == 0:
            self.log.debug("Success")
            del self.messages[err['identifier']]
            return
        self.log.debug("APNs Error encountered: {status}",
                       status=self.errors[err['status']])
        if err['status'] in [1, 255]:
            self.log.debug("Retrying...")
            resend = self.messages.get(err.get('identifier'))
            if resend is None:
                return
            apns_client = self.apns[resend["rel_channel"]]
            apns_client.gateway_server.send_notification(resend['token'],
                                                         resend['payload'],
                                                         err['identifier'],
                                                         )
