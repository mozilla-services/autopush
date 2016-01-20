"""Locally caching GCM SenderIDs

GCM requires a valid SenderID. One can use a single hard-coded value, but
that can be a problem if that lone SenderID is ever disqualified for some
reason. Instead, the server provides a senderid that the client can use.

This module uses a bucket named "oms_autopush" by default,
and stores the list of SenderIDs as a JSON string under the key of "senderids".
Please note that AWS uses the bucket ID as part of a TLS hostname. This
means that the Bucket ID cannot have ".", be over 255 characters in length,
and must be globally unique. (In our case, we use "oms_*" as a prefix. It's
an acronym for "org.mozilla.services")

The SenderID list has the following format:

     {"`senderID`": {"auth": "`API Key`"}, ...}

We use a dictionary of dictionaries to allow for future expansion.

You can either update the list of SenderIDs using the S3 console, or you
can load the SenderIDs by using the "--senderid_list" argument. It is
probably wiser to use the S3 console, otherwise there may be multiple
instances writing and the possiblity that the list of SenderIDs is
overwritten with older, less accurate values.

"""
import json
import random

from boto.s3.connection import S3Connection
from boto.s3.key import Key
from boto.exception import S3ResponseError
from twisted.python import log
from twisted.internet.threads import deferToThread
from twisted.internet.task import LoopingCall

# re-read from source every 15 minutes or so.
SENDERID_EXPRY = 15*60
DEFAULT_BUCKET = "oms_autopush"


class SenderIDs(object):
    """Handle Read, Write and cache of SenderID values from S3"""
    _expry = SENDERID_EXPRY
    _senderIDs = {}
    _use_s3 = True
    KEYNAME = "senderids"
    service = None

    def __init__(self, args):
        """Optionally load or fetch the set of SenderIDs from S3"""
        self.conn = S3Connection()
        self.ID = args.get("s3_bucket", DEFAULT_BUCKET).lower()
        self._expry = args.get("senderid_expry", SENDERID_EXPRY)
        self._use_s3 = args.get("use_s3", True)
        senderIDs = args.get("senderid_list", {})
        self.service = LoopingCall(self._refresh)
        if senderIDs:
            if type(senderIDs) is not dict:
                log.err("senderid_list is not a dict. Ignoring")
            else:
                # We're initializing, so it's ok to block.
                self.update(senderIDs)

    def start(self):
        if self._use_s3:
            log.msg("Starting SenderID service...")
            self.service.start(self._expry)

    def _write(self, senderIDs, *args):
        """Write a list of SenderIDs to S3"""
        bucket = self.conn.get_bucket(self.ID)
        key = Key(bucket)
        key.key = self.KEYNAME
        key.set_contents_from_string(json.dumps(senderIDs))
        self._senderIDs = senderIDs

    def _err(self, state):
        if (isinstance(state.value, S3ResponseError) and
                state.value.reason == 'Not Found'):
            self._create()

    def _create(self, *args):
        """Create a new bucket containing the senderIDs"""
        self.conn.create_bucket(self.ID)
        self._write(self._senderIDs)

    def _update_senderIDs(self, *args):
        bucket = self.conn.get_bucket(self.ID)
        key = Key(bucket)
        key.key = self.KEYNAME
        candidates = json.loads(key.get_contents_as_string())
        if candidates:
            if type(candidates) is not dict:
                log.err("Wrong data type stored for senderIDs. "
                        "Should be dict. Ignoring.")
                return
            return candidates

    def _set_senderIDs(self, senderIDs):
        if senderIDs:
            self._senderIDs = senderIDs

    def _refresh(self):
        """Refresh the senderIDs from the S3 bucket"""
        if not self._use_s3:
            return
        d = deferToThread(self._update_senderIDs, self._senderIDs)
        d.addCallback(self._set_senderIDs)
        d.addErrback(self._err)
        return d

    def update(self, senderIDs):
        """Initialize the S3 bucket containing the SenderIDs"""
        if not senderIDs:
            return
        if type(senderIDs) is not dict:
            log.err("Wrong data type for senderIDs. Should be dict.")
            return
        if not self._use_s3:
            # Skip using s3 (For debugging)
            if senderIDs:
                self._senderIDs = senderIDs
            return
        self._senderIDs = senderIDs
        self._create()

    def senderIDs(self):
        """Return a list of senderIDs"""
        return self._senderIDs

    def get_ID(self, id=None):
        """Return the associated record for a given SenderID"""
        if id is None:
            return self.choose_ID()
        record = self._senderIDs.get(id)
        return record

    def choose_ID(self):
        """Return a randomly selected SenderID, refreshing if required"""
        if not len(self._senderIDs):
            return None
        choice = random.choice(self._senderIDs.keys())
        record = self._senderIDs.get(choice)
        record["senderID"] = choice
        return record

    def stop(self):
        if self.service and self.service.running:
            log.msg("Stopping SenderID service...")
            self.service.stop()
