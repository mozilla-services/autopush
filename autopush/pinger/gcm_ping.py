# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import gcmclient as gcm

from twisted.python import log


class GCMPinger(object):
    gcm = None
    ttl = 60
    dryRun = 0
    collapseKey = "simplepush"

    def __init__(self, config):
        self.ttl = config.get("ttl", 60)
        self.dryRun = config.get("dryrun", False)
        self.collapseKey = config.get("collapseKey", "simplepush")
        self.gcm = gcm.GCM(config.get("apikey"))
        log.msg("Starting GCM pinger...")

    def ping(self, uaid, version, data, connectInfo):
        try:
            if connectInfo.get("type").lower() != "gcm":
                log.msg("connect info isn't gcm")
                return False
            if connectInfo.get("token") is None:
                log.msg("connect info missing 'token'")
                return False

            payload = self.gcm.JSONMessage(
                registration_ids=[connectInfo.get("token")],
                collapse_key=self.collapseKey,
                time_to_live=self.ttl,
                dry_run=self.dryRun,
                data={"Msg": data,
                      "Version": version}
            )
            reply = self.gcm.send(payload)
            # handle reply content
            # acks:
            #  for reg_id, msg_id in reply.success.items():
            # updates
            #  for old_id, new_id in reply.canonical.items():
            # naks:
            #  for reg_id, err_code in reply.failed.items():
            if reply.failed.items().length > 0:
                log.msg("Messages failed to be delivered.")
                return False
            # uninstall:
            #  for reg_id in reply.not_registered:
            # retries:
            #  if reply.needs_retry():
            #   retry = reply.retry()
            # after delay, send gcm.send(retry)
            return True
        except gcm.GCMAuthenticationError, e:
            log.err(e)
        except ValueError, e:
            log.err("GCM returned error %s" % e.args[0])
        except Exception, e:
            log.err("Unhandled exception caught %s" % e)
        return False
