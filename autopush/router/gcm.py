import gcmclient
import json

from twisted.python import log
from twisted.internet.threads import deferToThread

from autopush.router.interface import RouterException, RouterResponse


class GCMRouter(object):
    gcm = None
    ttl = 60
    dryRun = 0
    collapseKey = "simplepush"

    def __init__(self, ap_settings, router_conf):
        self.config = router_conf
        self.ttl = router_conf.get("ttl", 60)
        self.dryRun = router_conf.get("dryrun", False)
        self.collapseKey = router_conf.get("collapseKey", "simplepush")
        self.gcm = gcmclient.GCM(router_conf.get("apikey"))
        log.msg("Starting GCM router...")

    def register(self, uaid, router_data):
        if not router_data.get("token"):
            self._error("connect info missing 'token'", status=401)
        return router_data

    def route_notification(self, notification, uaid_data):
        router_data = uaid_data["router_data"]
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, router_data)

    def _route(self, notification, router_data):
        payload = gcmclient.JSONMessage(
            registration_ids=[router_data["token"]],
            collapse_key=self.collapseKey,
            time_to_live=self.ttl,
            dry_run=self.dryRun,
            data={"Msg": notification.data,
                  "Chid": notification.channel_id,
                  "Ver": notification.version}
        )
        try:
            result = self.gcm.send(payload)
        except gcmclient.GCMAuthenticationError, e:
            self._error("Authentication Error: %s" % e, 500)
        except Exception, e:
            self._error("Unhandled exception in GCM Routing: %s" % e, 500)
        return self._process_reply(result)

    def _error(self, err, status, **kwargs):
        log.err(err, **kwargs)
        raise RouterException(err, status_code=status, response_body=err)

    def _process_reply(self, reply):
        """Process GCM send reply"""
        # acks:
        #  for reg_id, msg_id in reply.success.items():
        # updates
        for old_id, new_id in reply.canonical.items():
            log.msg("GCM id changed : %s => " % old_id, new_id)
            return RouterResponse(status_code=503,
                                  response_body="Please try request again.",
                                  router_data=dict(token=new_id))
        # naks:
        # uninstall:
        for reg_id in reply.not_registered:
            log.msg("GCM no longer registered: %s" % reg_id)
            return RouterResponse(
                status_code=410,
                response_body="Endpoint requires client update",
                router_data={},
            )

        #  for reg_id, err_code in reply.failed.items():
        if len(reply.failed.items()) > 0:
            log.msg("GCM failures: %s" % json.dumps(reply.failed.items()))
            raise RouterException("GCM failure to deliver", status_code=503,
                                  response_body="Please try request later.")

        # retries:
        if reply.needs_retry():
            raise RouterException("GCM failure to deliver", status_code=503,
                                  response_body="Please try request later.")

        return RouterResponse(status_code=200, response_body="Message Sent")
