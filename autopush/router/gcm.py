import gcmclient
import json

from twisted.python import log
from twisted.internet import reactor
from twisted.internet.threads import deferToThread

from autopush.router.interface import RouterException, RouterResponse


class GCMRouter(object):
    gcm = None
    ttl = 60
    dryRun = 0
    collapseKey = "simplepush"
    messages = {}

    def __init__(self, ap_settings, router_conf):
        self.config = router_conf
        self.ttl = router_conf.get("ttl", 60)
        self.dryRun = router_conf.get("dryrun", False)
        self.collapseKey = router_conf.get("collapseKey", "simplepush")
        self.gcm = gcmclient.GCM(router_conf.get("apikey"))
        log.msg("Starting GCM bridge...")

    def register(self, uaid, router_data):
        if not router_data.get("token"):
            self._error("connect info missing 'token'", status=401)
        return router_data

    def route_notification(self, notification, uaid_data):
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, uaid_data)

    def _route(self, notification, uaid_data):
        payload = gcmclient.JSONMessage(
            registration_ids=[uaid_data["token"]],
            collapse_key=self.collapseKey,
            time_to_live=self.ttl,
            dry_run=self.dryRun,
            data={"Msg": notification.data,
                  "Chid": notification.channel_id,
                  "Ver": notification.version}
        )
        return self._send(payload)

    def _error(self, err, status, **kwargs):
        log.err(err, **kwargs)
        raise RouterException(err, status_code=status, response_body=err)

    def _send(self, payload, iter=0):
        try:
            result = self.gcm.send(payload)
            return self._result(result, iter)
        except gcmclient.GCMAuthenticationError, e:
            self._error("Authentication Error: %s" % e, 500)
        except Exception, e:
            self._error("Unhandled exception in GCM Routing: %s" % e, 500)

    def _result(self, reply, tries=0):
        # handle reply content
        # acks:
        #  for reg_id, msg_id in reply.success.items():
        # updates
        for old_id, new_id in reply.canonical.items():
            log.msg("GCM id changed : %s => " % old_id, new_id)
            self.storage.byToken('UPDATE', new_id)
            # No need to retransmit
        # naks:
        # uninstall:
        for reg_id in reply.not_registered:
            log.msg("GCM no longer registered: %s" % reg_id)
            self.storage.byToken('DELETE', reg_id)
            return False
        #  for reg_id, err_code in reply.failed.items():
        if len(reply.failed.items()) > 0:
            self._error("Messages failed to be delivered.")
            log.msg("GCM failures: %s" % json.dumps(reply.failed.items()))
            return False
        # retries:
        if reply.needs_retry():
            retry = reply.retry()
            if tries > 5:
                self._error("Failed repeated attempts to send message %s" %
                            retry)
                return False
            # include delay
            tries += 1
            reactor.callLater(5 * tries, deferToThread, self._send, retry,
                              tries)
        return RouterResponse(status_code=200, response_body="Message Sent")
