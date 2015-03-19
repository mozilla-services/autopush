# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import sys

from twisted.python import log
from apns import APNs, Payload


# https://github.com/djacobs/PyAPNs
class APNSPinger:
    apns = None

    def __init__(self, config):
        self.apns = APNs(use_sandbox=config.get("apns",{}).get("sandbox"),
                         cert_file=config.get("apns",{}).get("cert_file"),
                         key_file=config.get("apns",{}).get("key_file"))

    def ping(self, uaid, version, data):
        if self.storage is None:
            raise self.PingerUndefEx("No storage defined for Pinger")
        try:
            connectInfo = self.storage.get_connection(uaid)
            if connectInfo is False:
                return False
            cdata = json.loads(connectInfo.get("connect").get("s"))
            payload = Payload(alert=cdata["title"] | "SimplePush",
                              body=cdata["body"] | "New alert",
                              contentavailable=1,
                              custom={"version": version,
                                      "data": data})
            # TODO: Add listener for error handling.
            # apns_enhanced.gateway_server.register_response_listener(
            #   func({status:, identifier}){Retry logic})
            # apns_enhanced.gateway_server.send_notification(token,
            #   payload, identifier)
            self.apns.gateway_server.send_notification(cdata["token"], payload)
            return True
        except:
            e = sys.exc_info()[0]
            log.err("!! Ping exception: %s\n", e)
            return False
