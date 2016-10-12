"""GCM Router"""

import gcmclient
from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from autopush.exceptions import RouterException
from autopush.router.interface import RouterResponse
from autopush.utils import ms_time


class GCMRouter(object):
    """GCM Router Implementation"""
    log = Logger()
    dryRun = 0
    collapseKey = "simplepush"
    MAX_TTL = 2419200

    def __init__(self, ap_settings, router_conf):
        """Create a new GCM router and connect to GCM"""
        self.config = router_conf
        self.min_ttl = router_conf.get("ttl", 60)
        self.dryRun = router_conf.get("dryrun", False)
        self.collapseKey = router_conf.get("collapseKey", "simplepush")
        self.gcm = {}
        self.senderIDs = {}
        # Flatten the SenderID list from human readable and init gcmclient
        if not router_conf.get("senderIDs"):
            raise IOError("SenderIDs not configured.")
        for sid in router_conf.get("senderIDs"):
            auth = router_conf.get("senderIDs").get(sid).get("auth")
            self.senderIDs[sid] = auth
            try:
                self.gcm[sid] = gcmclient.GCM(auth)
            except:
                raise IOError("GCM Bridge not initiated in main")
        self.metrics = ap_settings.metrics
        self._base_tags = []
        self.router_table = ap_settings.router
        self.log.debug("Starting GCM router...")
        self.ap_settings = ap_settings

    def amend_msg(self, msg, data=None):
        if data is not None:
            msg["senderid"] = data.get('creds', {}).get('senderID')
        return msg

    def register(self, uaid, router_data, app_id, *args, **kwargs):
        """Validate that the GCM Instance Token is in the ``router_data``"""
        # "token" is the GCM registration id token generated by the client.
        if "token" not in router_data:
            raise self._error("connect info missing GCM Instance 'token'",
                              status=401)
        # senderid is the remote client's senderID value. This value is
        # very difficult for the client to change, and there was a problem
        # where some clients had an older, invalid senderID. We need to
        # be able to match senderID to it's corresponding auth key.
        # If the client has an unexpected or invalid SenderID,
        # it is impossible for us to reach them.
        senderid = app_id
        if senderid not in self.senderIDs:
            raise self._error("Invalid SenderID", status=410, errno=105,
                              uri=kwargs.get('uri'),
                              senderid=senderid)
        # Assign a senderid
        router_data["creds"] = {"senderID": senderid,
                                "auth": self.senderIDs[senderid]}
        return router_data

    def route_notification(self, notification, uaid_data):
        """Start the GCM notification routing, returns a deferred"""
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, uaid_data)

    def _route(self, notification, uaid_data):
        """Blocking GCM call to route the notification"""
        router_data = uaid_data["router_data"]
        data = {"chid": str(notification.channel_id)}
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

        # registration_ids are the GCM instance tokens (specified during
        # registration.
        router_ttl = min(self.MAX_TTL,
                         max(notification.ttl or 0, self.min_ttl))
        payload = gcmclient.JSONMessage(
            registration_ids=[router_data.get("token")],
            collapse_key=self.collapseKey,
            time_to_live=router_ttl,
            dry_run=self.dryRun or ("dryrun" in router_data),
            data=data,
        )
        creds = router_data.get("creds", {"senderID": "missing id"})
        try:
            gcm = self.gcm[creds['senderID']]
            result = gcm.send(payload)
        except KeyError:
            raise self._error("Server error, missing bridge credentials " +
                              "for %s" % creds.get("senderID"), 500)
        except gcmclient.GCMAuthenticationError as e:
            raise self._error("Authentication Error: %s" % e, 500)
        except Exception as e:
            raise self._error("Unhandled exception in GCM Routing: %s" % e,
                              500)
        self.metrics.increment("updates.client.bridge.gcm.attempted",
                               self._base_tags)
        return self._process_reply(result, uaid_data, ttl=router_ttl,
                                   notification=notification)

    def _error(self, err, status, **kwargs):
        """Error handler that raises the RouterException"""
        self.log.debug(err, **kwargs)
        return RouterException(err, status_code=status, response_body=err,
                               **kwargs)

    def _process_reply(self, reply, uaid_data, ttl, notification):
        """Process GCM send reply"""
        # acks:
        #  for reg_id, msg_id in reply.success.items():
        # updates
        for old_id, new_id in reply.canonical.items():
            self.log.info("GCM id changed : {old} => {new}",
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
            self.log.info("GCM no longer registered: %s" % reg_id)
            return RouterResponse(
                status_code=410,
                response_body="Endpoint requires client update",
                router_data={},
            )

        #  for reg_id, err_code in reply.failed.items():
        if len(reply.failed.items()) > 0:
            self.metrics.increment("updates.client.bridge.gcm.failed.failure",
                                   self._base_tags)
            self.log.info("GCM failures: {failed()}",
                          failed=lambda: repr(reply.failed.items()))
            self.router_table.register_user(
                {"uaid": uaid_data.get('uaid'),
                 "router_type": uaid_data.get("router_type", "gcm"),
                 "connected_at": ms_time(),
                 "critical_failure": "Client is unreachable due to a "
                                     "configuration error. Unable to "
                                     "send message.",
                 })
            raise RouterException("GCM unable to deliver", status_code=410,
                                  response_body="GCM recipient not available.")

        # retries:
        if reply.needs_retry():
            self.log.warn("GCM retry requested: {failed()}",
                          failed=lambda: repr(reply.failed.items()))
            self.metrics.increment("updates.client.bridge.gcm.failed.retry",
                                   self._base_tags)
            raise RouterException("GCM failure to deliver, retry",
                                  status_code=503,
                                  response_body="Please try request later.")

        self.metrics.increment("updates.client.bridge.gcm.succeeded",
                               self._base_tags)
        location = "%s/m/%s" % (self.ap_settings.endpoint_url,
                                notification.version)
        return RouterResponse(status_code=201, response_body="",
                              headers={"TTL": ttl,
                                       "Location": location},
                              logged_status=200)
