# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json

import gcmclient as gcm
from twisted.python import log


class GCMPinger:
    gcm = None
    # Set these in init
    ttl = 60
    dryRun = 0
    collapseKey = "simplepush"

    def __init__(self, config):
        self.ttl = config.get("gcm",
                              {}).get("ttl", 60)
        self.dryRun = config.get("gcm",
                                 {}).get("dryrun", False)
        self.collapseKey = config.get("gcm",
                                      {}).get("collapseKey", "simplepush")
        self.gcm = gcm.GCM(config.get("gcm",
                                      {}).get("apikey"))

    def ping(self, uaid, version, data):
        if self.storage is None:
            raise self.PingerUndefEx("No storage defined for Pinger")
        try:
            connectInfo = self.storage.get_connection(uaid)
            if connectInfo is False:
                return False
            cdata = json.loads(connectInfo.get("connect").get("s"))

            payload = gcm.JSONMessage(
                registration_ids=[cdata.get("RegID").get("s")],
                collapse_key=self.collapseKey,
                time_to_live=self.ttl,
                dry_run=self.dryRun,
                data={"Msg": data,
                      "Version": version}
            )
            reply = gcm.send(payload)
            # handle reply content
            ## acks:
            # for reg_id, msg_id in reply.success.items():
            ## updates
            # for old_id, new_id in reply.canonical.items():
            ## naks:
            # for reg_id, err_code in reply.failed.items():
            ## uninstall:
            # for reg_id in reply.not_registered:
            ## retries:
            # if reply.needs_retry():
            # retry = reply.retry()
            # after delay, send gcm.send(retry)
            return True
        except gcm.GCMAuthenticationError:
            raise self.BadPingerEx("GCM API Key is invalid")
        except ValueError, e:
            log.Error("GCM returned error %s" % e.args[0])
        except Exception, e:
            log.Error("Unhandled exception caught %s" % e)
        return False
