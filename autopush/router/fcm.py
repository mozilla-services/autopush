"""FCM Router"""
import gcmclient
import json

from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from autopush.router.interface import RouterException, RouterResponse


class FCMRouter(object):
    """FCM Router Implementation

    Note: FCM is a newer branch of GCM. While there's not much change
    required for the server, there is significant work required for the
    client. To that end, having a separate router allows the "older" GCM
    to persist and lets the client determine when they want to use the
    newer FCM route.
    """
    log = Logger()
    gcm = None
    dryRun = 0
    collapseKey = "simplepush"

    def __init__(self, ap_settings, router_conf):
        """Create a new FCM router and connect to FCM"""
        self.config = router_conf
        self.min_ttl = router_conf.get("ttl", 60)
        self.dryRun = router_conf.get("dryrun", False)
        self.collapseKey = router_conf.get("collapseKey", "webpush")
        self.senderID = router_conf.get("senderID")
        self.auth = router_conf.get("auth")
        self.metrics = ap_settings.metrics
        self._base_tags = []
        try:
            self.fcm = gcmclient.GCM(self.auth)
        except Exception as e:
            self.log.error("Could not instantiate FCM {ex}",
                           ex=e)
            raise IOError("FCM Bridge not initiated in main")
        self.log.debug("Starting FCM router...")

    def amend_msg(self, msg, data=None):
        if data is not None:
            msg["senderid"] = data.get('creds', {}).get('senderID')
        return msg

    def register(self, uaid, router_data, router_token=None, *kwargs):
        """Validate that the FCM Instance Token is in the ``router_data``"""
        if "token" not in router_data:
            raise self._error("connect info missing FCM Instance 'token'",
                              status=401)
        # router_token and router_data['token'] are semi-legacy from when
        # we were considering having multiple senderids for outbound
        # GCM support. That was abandoned, but it is still useful to
        # ensure that the client's senderid value matches what we need
        # it to be. (If the client has an unexpected or invalid SenderID,
        # it is impossible for us to reach them.
        if not (router_token == router_data['token'] == self.senderID):
            raise self._error("Invalid SenderID", status=410, errno=105)
        # Assign a senderid
        router_data["creds"] = {"senderID": self.senderID, "auth": self.auth}
        return router_data

    def route_notification(self, notification, uaid_data):
        """Start the FCM notification routing, returns a deferred"""
        router_data = uaid_data["router_data"]
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, router_data)

    def _route(self, notification, router_data):
        """Blocking FCM call to route the notification"""
        data = {"chid": notification.channel_id}
        # Payload data is optional. The endpoint handler validates that the
        # correct encryption headers are included with the data.
        if notification.data:
            mdata = self.config.get('max_data', 4096)
            if len(notification.data) > mdata:
                raise self._error("This message is intended for a " +
                                  "constrained device and is limited " +
                                  "to 3070 bytes. Converted buffer too " +
                                  "long by %d bytes" %
                                  (len(notification.data) - mdata),
                                  413, errno=104, log_exception=False)

            data['body'] = notification.data
            data['con'] = notification.headers['content-encoding']
            data['enc'] = notification.headers['encryption']

            if 'crypto-key' in notification.headers:
                data['cryptokey'] = notification.headers['crypto-key']
            elif 'encryption-key' in notification.headers:
                data['enckey'] = notification.headers['encryption-key']

        # registration_ids are the FCM instance tokens (specified during
        # registration.
        router_ttl = notification.ttl or 0
        payload = gcmclient.JSONMessage(
            registration_ids=[router_data.get("token")],
            collapse_key=self.collapseKey,
            time_to_live=max(self.min_ttl, router_ttl),
            dry_run=self.dryRun or ("dryrun" in router_data),
            data=data,
        )
        creds = router_data.get("creds", {"senderID": "missing id"})
        try:
            self.fcm.api_key = creds["auth"]
            result = self.fcm.send(payload)
        except KeyError:
            raise self._error("Server error, missing bridge credentials " +
                              "for %s" % creds.get("senderID"), 500)
        except gcmclient.GCMAuthenticationError as e:
            raise self._error("Authentication Error: %s" % e, 500)
        except Exception as e:
            raise self._error("Unhandled exception in FCM Routing: %s" % e,
                              500)
        self.metrics.increment("updates.client.bridge.gcm.attempted",
                               self._base_tags)
        return self._process_reply(result)

    def _error(self, err, status, **kwargs):
        """Error handler that raises the RouterException"""
        self.log.debug(err, **kwargs)
        return RouterException(err, status_code=status, response_body=err,
                               **kwargs)

    def _process_reply(self, reply):
        """Process FCM send reply"""
        # acks:
        #  for reg_id, msg_id in reply.success.items():
        # updates
        for old_id, new_id in reply.canonical.items():
            self.log.info("FCM id changed : {old} => {new}",
                          old=old_id, new=new_id)
            self.metrics.increment("updates.client.bridge.gcm.failed.rereg",
                                   self._base_tags)
            return RouterResponse(status_code=503,
                                  response_body="Please try request again.",
                                  router_data=dict(token=new_id))
        # naks:
        # uninstall:
        for reg_id in reply.not_registered:
            self.metrics.increment("updates.client.bridge.gcm.failed.unreg",
                                   self._base_tags)
            self.log.info("FCM no longer registered: %s" % reg_id)
            return RouterResponse(
                status_code=410,
                response_body="Endpoint requires client update",
                router_data={},
            )

        #  for reg_id, err_code in reply.failed.items():
        if len(reply.failed.items()) > 0:
            self.metrics.increment("updates.client.bridge.gcm.failed.failure",
                                   self._base_tags)
            self.log.critical("FCM failures: {failed()}",
                              failed=lambda: json.dumps(reply.failed.items()))
            raise RouterException("FCM failure to deliver", status_code=503,
                                  response_body="Please try request later.")

        # retries:
        if reply.needs_retry():
            self.log.warn("FCM retry requested: {failed()}",
                          failed=lambda: json.dumps(reply.failed.items()))
            self.metrics.increment("updates.client.bridge.gcm.failed.retry",
                                   self._base_tags)
            raise RouterException("FCM failure to deliver, retry",
                                  status_code=503,
                                  response_body="Please try request later.")

        self.metrics.increment("updates.client.bridge.gcm.succeeded",
                               self._base_tags)
        return RouterResponse(status_code=200, response_body="Message Sent")
