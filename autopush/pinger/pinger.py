# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json

from apns_ping import APNSPinger
from gcm_ping import GCMPinger

from twisted.python import log

__all__ = ["BadPingerEx", "PingerFailEx", "PingerUndefEx", "Pinger"]


class BadPingerEx(Exception):
    pass


class PingerFailEx(Exception):
    pass


class PingerUndefEx(Exception):
    pass


class Pinger:
    storage = None

    def __init__(self, storage, settings):
        self.storage = storage
        self.gcm = GCMPinger(settings)
        self.apns = APNSPinger(settings)

    def register(self, uaid, connect):
        ## Store the connect string to the database
        if self.storage is None:
            raise self.PingerUndefEx("No storage defined for Pinger")
        if self.storage.register_connect(uaid, connect) is False:
            raise self.PingerFailEx("Could not store registration info")
        return True

    def ping(self, uaid, version, data):
        if self.storage is None:
            raise self.PingerUndefEx("No storage defined for Pinger")
        try:
            connectInfo = self.storage.get_connection(uaid)
            if connectInfo is False:
                return False
            cdata = json.loads(connectInfo.get("connect").get("s"))
            ptype = cdata.get("type").tolower().strip
            if ptype == "gcm" and self.gcm is not None:
                return self.gcm.ping(uaid, version, data)
            if ptype == "apns" and self.apns is not None:
                return self.apns.ping(uaid, version, data)
            return False
        except Exception, e:
            log.Printf("Untrapped exception %s", e)
            return False

    def unregister(self, uaid):
        if self.storage is None:
            raise self.PingerUndefEx("No storage defined for Pinger")

        if self.storage.unregister(uaid) is False:
            raise self.PingerFailEx("Could not clear registration info")
        return True
