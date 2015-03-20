# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import sys

from twisted.python import log
from apns import APNs, Payload


# https://github.com/djacobs/PyAPNs
class APNSPinger(object):
    apns = None

    def __init__(self, config):
        self.apns = APNs(use_sandbox=config.get("apns", {}).get("sandbox"),
                         cert_file=config.get("apns", {}).get("cert_file"),
                         key_file=config.get("apns", {}).get("key_file"))
        self.default_title = config.get("apns",
                                        {}).get("default_title", "SimplePush")
        self.default_body = config.get("apns",
                                       {}).get("default_body", "New Alert")

    def ping(self, uaid, version, data, connectInfo):
        if self.storage is None:
            raise self.PingerUndefEx("No storage defined for Pinger")
        try:
            if connectInfo is False or connectInfo is None:
                return False
            if connectInfo.get("type").lower() != "apns":
                return False
            token = connectInfo.get("token")
            if token is None:
                return False
            payload = Payload(alert=connectInfo.get("title",
                                                    self.default_title),
                              body=connectInfo.get("body", self.default_body),
                              contentavailable=1,
                              custom={"version": version,
                                      "data": data})
            # TODO: Add listener for error handling.
            # apns_enhanced.gateway_server.register_response_listener(
            #   func({status:, identifier}){Retry logic})
            # apns_enhanced.gateway_server.send_notification(token,
            #   payload, identifier)
            self.apns.gateway_server.send_notification(token, payload)
            return True
        except:
            e = sys.exc_info()[0]
            log.err("!! Ping exception: %s\n", e)
            return False
