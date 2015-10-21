import json

from autopush.senderids import SenderIDs
from mock import Mock
from boto.exception import S3ResponseError
from moto import mock_s3, mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.trial import unittest


class SenderIDsTestCase(unittest.TestCase):
    def setUp(self):
        mock_dynamodb2().start()
        mock_s3().start()

    def tearDown(self):
        mock_dynamodb2().stop()
        mock_s3().stop()

    def test_success(self):
        settings = dict(
            s3_bucket="org.mozilla.autopush.test",
            senderid_expry=10,
            senderid_list=["test123", "test456"],
            )
        senderIDs = SenderIDs(settings)
        eq_(senderIDs.conn.get_bucket(settings.get("s3_bucket")).
            get_key('senderids').get_contents_as_string(),
            json.dumps(settings.get("senderid_list")))

        ok_(senderIDs.getID() in settings.get("senderid_list"))
        eq_(senderIDs.senderIDs(), settings.get("senderid_list"))
        senderIDs._expry = 0
        eq_(senderIDs.senderIDs(), settings.get("senderid_list"))

    def test_ensureCreated(self):
        settings = dict(
            s3_bucket="org.mozilla.autopush.test",
            senderid_expry=0,
            senderid_list=["test123", "test456"],
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
            s3_bucket="org.mozilla.autopush.test",
            senderid_expry=0,
            senderid_list=["test123", "test456"],
            )
        senderIDs = SenderIDs(settings)
        senderIDs.update(["test789"])
        eq_(senderIDs.conn.get_bucket(settings.get("s3_bucket")).
            get_key('senderids').get_contents_as_string(),
            '["test789"]')
