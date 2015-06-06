import gcmclient
import json

from twisted.internet import reactor
from twisted.python import log


class GCMRouter(object):
    gcm = None
    ttl = 60
    dryRun = 0
    collapseKey = "simplepush"
    messages = {}

    def __init__(self, config, storage):
        self.config = config
        self.ttl = config.get("ttl", 60)
        self.dryRun = config.get("dryrun", False)
        self.collapseKey = config.get("collapseKey", "simplepush")
        self.gcm = gcmclient.GCM(config.get("apikey"))
        self.storage = storage
        # self.pool = HTTPConnectionPool(reactor)
        log.msg("Starting GCM bridge...")

    def ping(self, uaid, version, data, connectInfo):
        try:
            if connectInfo.get("type").lower() != "gcm":
                self._error("connect info isn't gcm")
                return False
            if connectInfo.get("token") is None:
                self._error("connect info missing 'token'")
                return False

            payload = gcmclient.JSONMessage(
                registration_ids=[connectInfo.get("token")],
                collapse_key=self.collapseKey,
                time_to_live=self.ttl,
                dry_run=self.dryRun,
                data={"Msg": data,
                      "Ver": version}
            )
            return self._send(payload)
        except ValueError, e:
            self._error("GCM returned error %s" % e)
        return False

    def _error(self, err, **kwargs):
        log.err(err, **kwargs)
        return

    def _send(self, payload, iter=0):
        try:
            result = self.gcm.send(payload)
            return self._result(result, iter)
        except gcmclient.GCMAuthenticationError, e:
            self._error("Authentication Error: %s" % e)
        except Exception, e:
            self._error("Unhandled exception in GCM bridge: %s" % e)
        return False

    def _result(self, reply, iter=0):
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
            if iter > 5:
                self._error("Failed repeated attempts to send message %s" %
                            retry)
                return False
            # include delay
            iter = iter + 1
            reactor.callLater(5 * iter, self._send, retry, iter)
        return True
