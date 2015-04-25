# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import gcmclient
import json

from twisted.internet import reactor
from twisted.python import log


class GCMBridge(object):
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
                log.err("connect info isn't gcm")
                return False
            if connectInfo.get("token") is None:
                log.err("connect info missing 'token'")
                return False

            log.msg("Calling gcm.JSONMessage...")
            payload = gcmclient.JSONMessage(
                registration_ids=[connectInfo.get("token")],
                collapse_key=self.collapseKey,
                time_to_live=self.ttl,
                dry_run=self.dryRun,
                data={"Msg": data,
                      "Ver": version}
            )
            return self._send(payload)
        except gcmclient.GCMAuthenticationError, e:
            log.err("Authentication Error: %s" % e)
        except ValueError, e:
            log.err("GCM returned error %s" % e)
        except Exception, e:
            log.err("Unhandled exception caught %s" % e)
        return False

    def _error(self, err, **kwargs):
        log.err(err, **kwargs)
        return

    def _send(self, payload, iter=0):
        try:
            result = self.gcm.send(payload)
            return self._result(result, iter)
        except Exception, e:
            self._error(e)
        return False

    def _result(self, reply, iter=0):
        # handle reply content
        # acks:
        #  for reg_id, msg_id in reply.success.items():
        # updates
        for old_id, new_id in reply.canonical.items():
            self.storage.byToken('UPDATE', new_id)
            # No need to retransmit
        # naks:
        #  for reg_id, err_code in reply.failed.items():
        if len(reply.failed.items()) > 0:
            log.err("Messages failed to be delivered.")
            log.msg("GCM failures: %s" % json.dumps(reply.failed.items()))
            return False
        # uninstall:
        for reg_id in reply.not_registered:
            self.storage.byToken('DELETE', reg_id)
            return False
        # retries:
        if reply.needs_retry():
            retry = reply.retry()
            if iter > 5:
                log.err("Failed repeated attempts to send message %s" %
                        retry)
                return False
            # TODO: include delay
            iter = iter + 1
            reactor.callLater(5 * iter, self._send, retry, iter)
        return True
