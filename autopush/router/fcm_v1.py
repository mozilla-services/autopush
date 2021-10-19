"""FCM v1 HTTP Router"""
import json
from math import ceil

from typing import Any  # noqa

from twisted.internet.error import ConnectError, TimeoutError
from twisted.logger import Logger

from autopush.exceptions import RouterException
from autopush.metrics import make_tags
from autopush.router.interface import RouterResponse
from autopush.router.fcm import FCMRouter
from autopush.router.fcmv1client import (
    FCMv1,
    FCMAuthenticationError,
    FCMNotFoundError
)
from autopush.types import JSONDict  # noqa

# the universal default for this is 4096, which is far too
# large for FCM. The final payload size of the encoded data, plus
# encryption headers must fit in the 4096 byte FCM payload.
# Since the body is re-encoded base64, we reduce the message
# size accordingly
MAX_FCM_DATA = 3015


class FCMv1Router(FCMRouter):
    """FCM v1 HTTP Router Implementation

    Note: FCM v1 is a newer version of the FCM HTTP API.
    """

    def __init__(self, conf, router_conf, metrics):
        """Create a new FCM router and connect to FCM"""
        self.conf = conf
        self.router_conf = router_conf
        self.metrics = metrics
        self.min_ttl = router_conf.get("ttl", 60)
        self.dryRun = router_conf.get("dryrun", False)
        self.collapseKey = router_conf.get("collapseKey", "webpush")
        self.version = router_conf["version"]
        self.log = Logger()
        self.clients = {}
        try:
            for (sid, creds) in router_conf["creds"].items():
                self.clients[sid] = FCMv1(
                    project_id=creds["projectid"],
                    service_cred_path=creds["auth"],
                    logger=self.log,
                    metrics=self.metrics)
        except Exception as e:
            self.log.error("Could not instantiate FCMv1: missing credentials,",
                           ex=e)
            raise IOError("FCMv1 Bridge not initiated in main")
        self._base_tags = ["platform:fcmv1"]
        self.log.debug("Starting FCMv1 router...")

    def amend_endpoint_response(self, response, router_data):
        # type: (JSONDict, JSONDict) -> None
        response["senderid"] = router_data["app_id"]

    def register(self, uaid, router_data, app_id, *args, **kwargs):
        # type: (str, JSONDict, str, *Any, **Any) -> None
        """Validate that the FCM Instance Token is in the ``router_data``"""
        # "token" is the FCM token generated by the client.
        if "token" not in router_data:
            raise self._error("connect info missing FCM Instance 'token'",
                              status=401,
                              uri=kwargs.get('uri'),
                              senderid=repr(app_id))
        if app_id not in self.clients:
            raise self._error("Invalid SenderID", status=410, errno=105)
        router_data["app_id"] = app_id

    def route_notification(self, notification, uaid_data):
        """Start the FCM notification routing, returns a deferred"""
        router_data = uaid_data["router_data"]
        return self._route(notification, router_data)

    def _route(self, notification, router_data):
        """Blocking FCM call to route the notification"""
        # THIS MUST MATCH THE CHANNELID GENERATED BY THE REGISTRATION SERVICE
        # Currently this value is in hex form.
        data = {"chid": notification.channel_id.hex}
        if not router_data.get("token"):
            raise self._error("No registration token found. "
                              "Rejecting message.",
                              410, errno=106, log_exception=False)
        # Payload data is optional. The endpoint handler validates that the
        # correct encryption headers are included with the data.
        if notification.data:
            data['con'] = notification.headers.get('encoding')
            mdata = self.router_conf.get('max_data', MAX_FCM_DATA)
            if data['con'] != "aes128gcm":
                # aes128gcm does not include headers, so they get more data.
                if 'encryption' in notification.headers:
                    data['enc'] = notification.headers['encryption']
                if 'crypto_key' in notification.headers:
                    data['cryptokey'] = notification.headers['crypto_key']
                elif 'encryption_key' in notification.headers:
                    data['enckey'] = notification.headers['encryption_key']
                data["body"] = ""
                mdata = mdata - len(json.dumps(data))
            data['body'] = notification.data
            if notification.data_length > mdata:
                # take a guess at about how long the decoded message buffer
                # needs to be.
                suggest_length = int(
                    ceil((notification.data_length - mdata) / 1.3))
                raise self._error("This message is intended for a "
                                  "constrained device and is limited "
                                  "to {} bytes. Message too "
                                  "long by about {} bytes".format(
                                      mdata, suggest_length),
                                  413, errno=104, log_exception=False)
            # check the size of the outbound message data, again.
            payload_size = len(json.dumps(data))
            # 4096 is the hard limit for FCM payloads. Trap just in case
            # our math was wrong.
            if payload_size > 4096:
                raise self._error(
                    "Final composed message payload too long for recipient: "
                    "{} bytes. Please try a shorter message.".format(
                        payload_size,
                    ),
                    413, errno=104, log_exception=False)
        # registration_ids are the FCM instance tokens (specified during
        # registration.
        router_ttl = min(self.MAX_TTL,
                         max(self.min_ttl, notification.ttl or 0))
        try:
            d = self.clients[router_data["app_id"]].send(
                token=router_data.get("token"),
                payload={
                    "collapse_key": self.collapseKey,
                    "data_message": data,
                    "dry_run": self.dryRun or ('dryrun' in router_data),
                    "ttl": router_ttl
                })
        except KeyError:
            raise self._error("Invalid Application ID specified",
                              404, errno=106, log_exception=False)
        d.addCallback(
            self._process_reply, notification, router_data, router_ttl
        )
        d.addErrback(
            self._process_error
        )
        return d

    def _process_error(self, failure):
        err = failure.value
        if isinstance(err, FCMAuthenticationError):
            self.log.error("FCM Authentication Error: {}".format(err))
            raise RouterException("Server error", status_code=500, errno=901)
        if isinstance(err, TimeoutError):
            self.log.warn("FCM Timeout: %s" % err)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="timeout",
                                       error=502,
                                       errno=903,
                                       ))
            raise RouterException("Server error", status_code=502,
                                  errno=903,
                                  log_exception=False)
        if isinstance(err, ConnectError):
            self.log.warn("FCM Unavailable: %s" % err)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="connection_unavailable",
                                       error=502,
                                       errno=902,
                                       ))
            raise RouterException("Server error", status_code=502,
                                  errno=902,
                                  log_exception=False)
        if isinstance(err, FCMNotFoundError):
            self.log.debug("FCM Recipient not found: %s" % err)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="recipient_gone",
                                       error=404,
                                       errno=106,
                                   ))
            raise RouterException("FCM Recipient no longer available",
                                  status_code=404,
                                  errno=106,
                                  log_exception=False)
        if isinstance(err, RouterException):
            self.log.warn("FCM Error: {}".format(err))
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="server_error",
                                       error=502,
                                       errno=0))
        return failure

    def _error(self, err, status, **kwargs):
        """Error handler that raises the RouterException"""
        self.log.debug(err, **kwargs)
        return RouterException(err, status_code=status, response_body=err,
                               **kwargs)

    def _process_reply(self, reply, notification, router_data, ttl):
        """Process FCM send reply"""
        # Failures are returned as non-200 messages (404, 410, etc.)
        self.metrics.increment("notification.bridge.sent",
                               tags=self._base_tags)
        self.metrics.increment("notification.message_data",
                               notification.data_length,
                               tags=make_tags(self._base_tags,
                                              destination="Direct"))
        location = "%s/m/%s" % (self.conf.endpoint_url, notification.version)
        return RouterResponse(status_code=201, response_body="",
                              headers={"TTL": ttl,
                                       "Location": location},
                              logged_status=200)
