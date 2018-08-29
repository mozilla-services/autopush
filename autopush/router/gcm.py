"""GCM Router"""
from typing import Any  # noqa

from requests.exceptions import ConnectionError, Timeout
from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from autopush.exceptions import RouterException
from autopush.metrics import make_tags
from autopush.router import gcmclient
from autopush.router.interface import RouterResponse
from autopush.types import JSONDict  # noqa


class GCMRouter(object):
    """GCM Router Implementation"""
    log = Logger()
    dryRun = 0
    collapseKey = "simplepush"
    MAX_TTL = 2419200

    def __init__(self, conf, router_conf, metrics):
        """Create a new GCM router and connect to GCM"""
        self.conf = conf
        self.router_conf = router_conf
        self.metrics = metrics
        self.min_ttl = router_conf.get("ttl", 60)
        self.dryRun = router_conf.get("dryrun", False)
        self.collapseKey = router_conf.get("collapseKey")
        timeout = router_conf.get("timeout", 10)
        self.gcm = {}
        self.senderIDs = {}
        # Flatten the SenderID list from human readable and init gcmclient
        if not router_conf.get("senderIDs"):
            raise IOError("SenderIDs not configured.")
        for sid in router_conf.get("senderIDs"):
            auth = router_conf.get("senderIDs").get(sid).get("auth")
            self.senderIDs[sid] = auth
            self.gcm[sid] = gcmclient.GCM(auth, timeout=timeout)
        self._base_tags = ["platform:gcm"]
        self.log.debug("Starting GCM router...")

    def amend_endpoint_response(self, response, router_data):
        # type: (JSONDict, JSONDict) -> None
        response["senderid"] = router_data.get('creds', {}).get('senderID')

    def register(self, uaid, router_data, app_id, *args, **kwargs):
        # type: (str, JSONDict, str, *Any, **Any) -> None
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

    def route_notification(self, notification, uaid_data):
        """Start the GCM notification routing, returns a deferred"""
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, uaid_data)

    def _route(self, notification, uaid_data):
        """Blocking GCM call to route the notification"""
        router_data = uaid_data["router_data"]
        # THIS MUST MATCH THE CHANNELID GENERATED BY THE REGISTRATION SERVICE
        # Currently this value is in hex form.
        data = {"chid": notification.channel_id.hex}
        # Payload data is optional. The endpoint handler validates that the
        # correct encryption headers are included with the data.
        if notification.data:
            mdata = self.router_conf.get('max_data', 4096)
            if notification.data_length > mdata:
                raise self._error("This message is intended for a " +
                                  "constrained device and is limited " +
                                  "to 3070 bytes. Converted buffer too " +
                                  "long by %d bytes" %
                                  (notification.data_length - mdata),
                                  413, errno=104, log_exception=False)

            data['body'] = notification.data
            data['con'] = notification.headers['encoding']

            if 'encryption' in notification.headers:
                data['enc'] = notification.headers.get('encryption')
            if 'crypto_key' in notification.headers:
                data['cryptokey'] = notification.headers['crypto_key']
            elif 'encryption_key' in notification.headers:
                data['enckey'] = notification.headers['encryption_key']

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
        try:
            gcm = self.gcm[router_data['creds']['senderID']]
            result = gcm.send(payload)
        except RouterException:
            raise  # pragma nocover
        except KeyError:
            self.log.critical("Missing GCM bridge credentials")
            raise RouterException("Server error", status_code=500,
                                  errno=900)
        except gcmclient.GCMAuthenticationError as e:
            self.log.error("GCM Authentication Error: %s" % e)
            raise RouterException("Server error", status_code=500,
                                  errno=901)
        except ConnectionError as e:
            self.log.warn("GCM Unavailable: %s" % e)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="connection_unavailable"))
            raise RouterException("Server error", status_code=502,
                                  errno=902,
                                  log_exception=False)
        except Timeout as e:
            self.log.warn("GCM Timeout: %s" % e)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="timeout"))
            raise RouterException("Server error", status_code=502,
                                  errno=903,
                                  log_exception=False)
        except Exception as e:
            self.log.error("Unhandled exception in GCM Routing: %s" % e)
            raise RouterException("Server error", status_code=500)
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
        for old_id, new_id in reply.canonicals.items():
            self.log.debug("GCM id changed : {old} => {new}",
                           old=old_id, new=new_id)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(self._base_tags,
                                                  reason="reregister"))
            return RouterResponse(status_code=503,
                                  response_body="Please try request again.",
                                  router_data=dict(token=new_id))
        # naks:
        # uninstall:
        for reg_id in reply.not_registered:
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(self._base_tags,
                                                  reason="unregistered"))
            self.log.debug("GCM no longer registered: %s" % reg_id)
            return RouterResponse(
                status_code=410,
                response_body="Endpoint requires client update",
                router_data={},
            )

        #  for reg_id, err_code in reply.failed.items():
        if len(reply.failed.items()) > 0:
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(self._base_tags,
                                                  reason="failure"))
            self.log.debug("GCM failures: {failed()}",
                           failed=lambda: repr(reply.failed.items()))
            raise RouterException("GCM unable to deliver", status_code=410,
                                  response_body="GCM recipient not available.",
                                  log_exception=False,
                                  )

        # retries:
        if reply.retry_after:
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(self._base_tags,
                                                  reason="retry"))
            self.log.warn("GCM retry requested: {failed()}",
                          failed=lambda: repr(reply.failed.items()))
            raise RouterException("GCM failure to deliver, retry",
                                  status_code=503,
                                  headers={"Retry-After": reply.retry_after},
                                  response_body="Please try request "
                                                "in {} seconds.".format(
                                       reply.retry_after
                                  ),
                                  log_exception=False)

        self.metrics.increment("notification.bridge.sent",
                               tags=self._base_tags)
        self.metrics.increment("notification.message_data",
                               notification.data_length,
                               tags=make_tags(self._base_tags,
                                              destination='Direct'))
        location = "%s/m/%s" % (self.conf.endpoint_url, notification.version)
        return RouterResponse(status_code=201, response_body="",
                              headers={"TTL": ttl,
                                       "Location": location},
                              logged_status=200)
