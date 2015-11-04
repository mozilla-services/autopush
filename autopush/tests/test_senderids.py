import json

from autopush.senderids import SenderIDs
from mock import Mock
from boto.exception import S3ResponseError
from moto import mock_s3, mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.trial import unittest

TEST_BUCKET = "oma_test"

test_list = {"test123": {"auth": "abc"}, "test456": {"auth": "def"}}


class SenderIDsTestCase(unittest.TestCase):
    def setUp(self):
        mock_dynamodb2().start()
        mock_s3().start()

    def tearDown(self):
        mock_dynamodb2().stop()
        mock_s3().stop()

    def test_nos3(self):
        senderIDs = SenderIDs(dict(use_s3=False))
        senderIDs.conn = Mock()
        senderIDs._refresh()
        eq_(senderIDs.conn.get_bucket.call_count, 0)
        senderIDs.update({})
        eq_(senderIDs.conn.get_bucket.call_count, 0)

    def test_bad_init(self):
        senderIDs = SenderIDs(dict(senderid_list="[Update"))
        eq_(senderIDs._senderIDs, {})

    def test_success(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=10,
            senderid_list=test_list,
            )
        senderIDs = SenderIDs(settings)
        eq_(senderIDs.conn.get_bucket(settings.get("s3_bucket")).
            get_key('senderids').get_contents_as_string(),
            json.dumps(settings.get("senderid_list")))

        eq_(senderIDs.senderIDs(), settings.get("senderid_list"))
        # getID may modify the record in memory adding a field.
        got = senderIDs.getID()
        ok_(got.get('senderID') in settings.get("senderid_list").keys())
        ok_(got.get('auth') ==
            settings.get("senderid_list")[got.get('senderID')]['auth'])
        old = senderIDs._updated
        senderIDs._expry = 0
        senderIDs.senderIDs()
        ok_(senderIDs._updated != old)

    def test_ensureCreated(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        senderIDs = SenderIDs(settings)
        oldConn = senderIDs.conn
        senderIDs.conn = Mock()
        senderIDs.conn.get_bucket.side_effect = S3ResponseError(403, "", "")
        senderIDs._create = Mock()
        senderIDs._updated = 0
        senderIDs._refresh()
        ok_(senderIDs._create.called)
        senderIDs.conn = oldConn

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

    def test_bad_update(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        senderIDs = SenderIDs(settings)
        update = {}
        senderIDs.update(update)
        eq_(senderIDs._senderIDs, test_list)
        senderIDs.update([123])
        eq_(senderIDs._senderIDs, test_list)

    def test_get_record(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        senderIDs = SenderIDs(settings)
        fetch = senderIDs.get('test123')
        eq_(fetch, {"senderID": "test123", "auth": "abc"})

    def test_refresh(self):
        settings = dict(
            s3_bucket=TEST_BUCKET,
            senderid_expry=0,
            senderid_list=test_list,
            )
        senderIDs = SenderIDs(settings)
        bucket = senderIDs.conn.get_bucket(senderIDs.ID)
        senderIDs._write(bucket, "[Invalid")
        senderIDs._senderIDs = {}
        senderIDs._expry = 0
        senderIDs._refresh()
        eq_(senderIDs._senderIDs, {})
