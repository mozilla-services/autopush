"""Locally caching GCM SenderIDs

GCM requires a valid SenderID. One can use a single hard-coded value, but
that can be a problem if that lone SenderID is ever disqualified for some
reason. Instead, the server provides a senderid that the client can use.

This module uses a bucket named "org.mozilla.services.autopush" by default,
and stores the list of SenderIDs as a JSON string under the key of "senderids".

You can either update the list of SenderIDs using the S3 console, or you
can load the SenderIDs by using the "--senderid_list" argument. It is
probably wiser to use the S3 console, otherwise there may be multiple
instances writing and the possiblity that the list of SenderIDs is
overwritten with older, less accurate values.

"""
import time
import json
import random

from boto.exception import S3ResponseError
from boto.s3.connection import S3Connection
from boto.s3.key import Key

# re-read from source every 15 minutes or so.
SENDERID_EXPRY = 15*60
DEFAULT_BUCKET = "org.mozilla.services.autopush"


class SenderIDs(object):
    """Handle Read, Write and cache of SenderID values from S3"""
    _updated = 0
    _expry = SENDERID_EXPRY
    _senderIDs = []
    KEYNAME = "senderids"

    def _write(self, bucket, senderIDs):
        """Write a list of SenderIDs to S3"""
        key = Key(bucket)
        key.key = self.KEYNAME
        key.set_contents_from_string(json.dumps(senderIDs))
        self._senderIDs = senderIDs
        self._updated = time.time()

    def _create(self, senderIDs):
        """Create a new bucket containing the senderIDs"""
        bucket = self.conn.create_bucket(self.ID)
        self._write(bucket, senderIDs)

    def _refresh(self):
        """Refresh the senderIDs from the S3 bucket"""
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
        """Update the S3 bucket containing the SenderIDs"""
        try:
            bucket = self.conn.get_bucket(self.ID)
            self._write(bucket, senderIDs)
        except S3ResponseError:
            self._create(senderIDs)

    def senderIDs(self):
        """Return a list of senderIDs, refreshing if required"""
        if time.time() > self._updated + self._expry:
            self._refresh()
        return self._senderIDs

    def getID(self):
        """Return a randomly selected SenderID, refreshing if required"""
        self._refresh()
        return random.choice(self._senderIDs)

    def __init__(self, args):
        """Optionally load or fetch the set of SenderIDs from S3"""
        self.conn = S3Connection()
        self.ID = args.get("s3_bucket", DEFAULT_BUCKET)
        self._expry = args.get("senderid_expry", SENDERID_EXPRY)
        senderIDs = args.get("senderid_list", [])
        if senderIDs:
            self.update(senderIDs)
        self._refresh()
