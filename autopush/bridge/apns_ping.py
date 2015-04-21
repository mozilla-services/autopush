# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from twisted.python import log
import apns


# https://github.com/djacobs/PyAPNs
class APNSBridge(object):
    apns = None

    def __init__(self, config):
        self.apns = apns.APNs(use_sandbox=config.get("sandbox", False),
                              cert_file=config.get("cert_file"),
                              key_file=config.get("key_file"))
        self.default_title = config.get("default_title", "SimplePush")
        self.default_body = config.get("default_body", "New Alert")
        log.msg("Starting APNS bridge...")

    def ping(self, uaid, version, data, connectInfo):
        try:
            if connectInfo.get("type").lower() != "apns":
                return False
            token = connectInfo.get("token")
            if token is None:
                return False
            payload = apns.Payload(alert=connectInfo.get("title",
                                                         self.default_title),
                                   content_available=1,
                                   custom={"Msg": data,
                                           "Version": version})
            # TODO: Add listener for error handling.
            # apns_enhanced.gateway_server.register_response_listener(
            #   func({status:, identifier}){Retry logic})
            # apns_enhanced.gateway_server.send_notification(token,
            #   payload, identifier)
            self.apns.gateway_server.send_notification(token, payload)
            return True
        except Exception, e:
            log.err(e)
            return False
