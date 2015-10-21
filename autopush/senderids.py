# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from boto.exception import S3ResponseError
from boto.s3.connection import S3Connection
from boto.s3.key import Key

import time
import json
import random

# re-read from source every 15 minutes or so.
SENDERID_EXPRY = 15*60
DEFAULT_BUCKET = "org.mozilla.services.autopush"


class SenderIDs(object):
    _updated = 0
    _expry = SENDERID_EXPRY
    _senderIDs = []
    KEYNAME = "senderids"

    def _write(self, bucket, senderIDs):
        key = Key(bucket)
        key.key = self.KEYNAME
        key.set_contents_from_string(json.dumps(senderIDs))
        self._senderIDs = senderIDs
        self._updated = time.time()

    def _create(self, senderIDs):
        """ Create a new bucket containing the senderIDs"""
        bucket = self.conn.create_bucket(self.ID)
        self._write(bucket, senderIDs)

    def _refresh(self):
        """ Refresh the senderIDs from the S3 bucket """
        # Only refresh if needed.
        if time.time() < self._updated + self._expry:
            return
        try:
            bucket = self.conn.get_bucket(self.ID)
            key = Key(bucket)
            key.key = self.KEYNAME
            self._senderIDs = json.loads(key.get_contents_as_string())
        except S3ResponseError:
            self._create(self._senderIDs)

    def update(self, senderIDs):
        """ Update the S3 bucket containing the SenderIDs"""
        try:
            bucket = self.conn.get_bucket(self.ID)
            self._write(bucket, senderIDs)
        except S3ResponseError:
            self._create(senderIDs)

    def senderIDs(self):
        """Return a list of senderIDs, refreshing if required """
        if time.time() > self._updated + self._expry:
            self._refresh()
        return self._senderIDs

    def getID(self):
        self._refresh()
        return random.choice(self._senderIDs)

    def __init__(self, args):
        self.conn = S3Connection()
        self.ID = args.get("s3_bucket", DEFAULT_BUCKET)
        self._expry = args.get("senderid_expry", SENDERID_EXPRY)
        senderIDs = args.get("senderid_list", [])
        if len(senderIDs):
            self.update(senderIDs)
        self._refresh()
