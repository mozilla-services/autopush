# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
from apns_ping import APNSBridge
from gcm_ping import GCMBridge

from twisted.python import log

__all__ = ["BridgeUndefEx", "BridgeFailEx", "Bridge"]


class BridgeUndefEx(Exception):
    pass


class BridgeFailEx(Exception):
    pass


class Bridge(object):
    storage = None

    def __init__(self, storage, settings):
        if storage is None:
            raise BridgeUndefEx("No storage defined for Bridge")
        self.storage = storage
        self.gcm = None
        self.apns = None
        if settings.get('gcm'):
            self.gcm = GCMBridge(settings.get('gcm'))
        if settings.get('apns'):
            self.apns = APNSBridge(settings.get('apns'))

    def register(self, uaid, connect):
        # Store the connect string to the database
        if self.storage is None:
            raise BridgeUndefEx("No storage defined for Bridge")
        if connect is None or connect is False:
            return None
        try:
            if self.storage.register_connect(uaid, connect) is False:
                log.err("Failed to register connection for %s:%s" %
                        (uaid, connect))
                raise BridgeFailEx("Unable to register connection")
        except Exception, e:
            log.err(e)
            raise
        return True

    def ping(self, uaid, version, data, connect):
        try:
            if connect is None or connect is False:
                return False
            connectInfo = json.loads(connect)
            ptype = connectInfo.get("type").lower().strip()
            if ptype == "gcm" and self.gcm is not None:
                return self.gcm.ping(uaid, version, data, connectInfo)
            if ptype == "apns" and self.apns is not None:
                return self.apns.ping(uaid, version, data, connectInfo)
            log.err("Unknown connection type specified: ptype")
            return False
        except Exception, e:
            log.err(e)
            return False

    def unregister(self, uaid):
        if self.storage is None:
            raise BridgeUndefEx("No storage defined for Bridge")
        if self.storage.unregister(uaid) is False:
            return False
        return True
