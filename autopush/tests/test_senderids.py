import json
import twisted

from autopush.senderids import SenderIDs
from mock import Mock, patch
from boto.exception import S3ResponseError
from boto.s3.key import Key
from moto import mock_s3, mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.trial import unittest

TEST_BUCKET = "oma_test"

test_list = {"test123": {"senderID": "test123", "auth": "abc"},
             "test456": {"senderID": "test456", "auth": "def"}}


class SenderIDsTestCase(unittest.TestCase):
    def setUp(self):
        mock_dynamodb2().start()
        mock_s3().start()
        self.senderIDs = None

    def tearDown(self):
        mock_dynamodb2().stop()
        mock_s3().stop()
        if self.senderIDs:
            self.senderIDs.stop()

    def test_nos3(self):
        self.senderIDs = SenderIDs(dict(use_s3=False))
        self.senderIDs.conn = Mock()
        self.senderIDs._refresh()
        eq_(self.senderIDs.conn.get_bucket.call_count, 0)

    def test_bad_init(self):
        self.senderIDs = SenderIDs(dict(senderid_list="[Update"))
        eq_(self.senderIDs._senderIDs, {})

    def test_success(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=10,
            senderid_list=test_list,
            )
        self.senderIDs = SenderIDs(settings)
        eq_(self.senderIDs.conn.get_bucket(settings.get("s3_bucket")).
            get_key('senderids').get_contents_as_string(),
            json.dumps(settings.get("senderid_list")))

        eq_(self.senderIDs.senderIDs(), settings.get("senderid_list"))
        # choose_ID may modify the record in memory adding a field.
        got = self.senderIDs.choose_ID()
        ok_(got.get('senderID') in settings.get("senderid_list").keys())
        ok_(got.get('auth') ==
            settings.get("senderid_list")[got.get('senderID')]['auth'])
        self.senderIDs._expry = 0

    def test_ensureCreated(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        self.senderIDs = SenderIDs(settings)
        oldConn = self.senderIDs.conn
        self.senderIDs.conn = Mock()
        self.senderIDs.conn.get_bucket.side_effect = \
            [S3ResponseError(404, "Not Found", ""), None]
        self.senderIDs._create = Mock()

        def handle_finish(*args):
            ok_(self.senderIDs._create.called)
            self.senderIDs.conn = oldConn

        d = self.senderIDs._refresh()
        d.addBoth(handle_finish)
        return d

    def test_update(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        senderIDs = SenderIDs(settings)
        update = {"test789": {"auth": "ghi"}}

        senderIDs.update(update)
        eq_(senderIDs.conn.get_bucket(settings.get("s3_bucket")).
            get_key('senderids').get_contents_as_string(),
            json.dumps(update))
        return

    def test_bad_update(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        self.senderIDs = SenderIDs(settings)
        update = {}
        d = self.senderIDs.update(update)
        eq_(d, None)
        eq_(self.senderIDs._senderIDs, test_list)
        self.senderIDs.update([123])
        eq_(d, None)
        eq_(self.senderIDs._senderIDs, test_list)
        self.senderIDs.conn.create_bucket(TEST_BUCKET)
        # Try a valid, but incorrectly formatted set of senderIDs
        tkey = Key(self.senderIDs.conn.get_bucket(TEST_BUCKET))
        tkey.key = self.senderIDs.KEYNAME
        tkey.set_contents_from_string("[123,456]")
        self.senderIDs._update_senderIDs()
        eq_(self.senderIDs._senderIDs, test_list)
        return

    def test_get_record(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        self.senderIDs = SenderIDs(settings)
        fetch = self.senderIDs.get_ID('test123')
        eq_(fetch, {"senderID": "test123", "auth": "abc"})
        fetch = self.senderIDs.get_ID()
        ok_(fetch is not None)
        return self.senderIDs.stop()

    def test_get_norecord(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
        )
        self.senderIDs = SenderIDs(settings)
        fetch = self.senderIDs.choose_ID()
        eq_(fetch, None)
        return

    def test_refresh(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        self.senderIDs = SenderIDs(settings)
        self.senderIDs._senderIDs = {}
        self.senderIDs._expry = 0
        twisted.internet.base.DelayedCall.debug = True

        def finish_handler(*args):
            eq_(self.senderIDs._senderIDs, test_list)

        d = self.senderIDs._refresh()
        d.addBoth(finish_handler)
        return d

    @patch("autopush.senderids.LoopingCall",
           spec=twisted.internet.task.LoopingCall)
    def test_start(self, fts):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        self.senderIDs = SenderIDs(settings)
        self.senderIDs.start()
        ok_(self.senderIDs.service.start.called)
        fts.running = True
        self.senderIDs.stop()
        ok_(self.senderIDs.service.stop.called)
