import json

import twisted
from cyclone.web import Application
from twisted.trial import unittest
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_

from autopush.db import (
    create_rotating_message_table,
)
from autopush.log_check import LogCheckHandler
from autopush.settings import AutopushSettings
from twisted.internet.defer import Deferred


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()
    create_rotating_message_table()


def tearDown():
    mock_dynamodb2.stop()


class LogCheckTestCase(unittest.TestCase):

    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        from twisted.logger import Logger

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.request_mock = Mock(body=b'', arguments={},
                                 headers={"ttl": "0"},
                                 host='example.com:8080')
        self.lch = LogCheckHandler(Application(),
                                   self.request_mock,
                                   ap_settings=settings)

        self.finish_deferred = Deferred()
        self.lch.finish = lambda: self.finish_deferred.callback(True)
        self.lch.set_status = Mock()
        self.lch.write = Mock()
        self.lch.log = Mock(spec=Logger)

    def test_get_err(self):

        def handle_finish(value):
            call_args = self.lch.log.error.call_args[1]
            eq_(call_args.get('format'), 'Test Error Message')
            eq_(call_args.get('status_code'), 418)
            write_arg = json.loads(self.lch.write.call_args[0][0])
            eq_(write_arg.get('code'), 418)
            eq_(write_arg.get('message'), "ERROR:Success")

        self.finish_deferred.addCallback(handle_finish)
        self.lch.get(None)
        return self.finish_deferred

    def test_get_crit(self):

        def handle_finish(value):
            call_args = self.lch.log.failure.call_args[1]
            eq_(call_args.get('status_code'), 418)
            write_args = json.loads(self.lch.write.call_args[0][0])
            eq_(write_args.get('code'), 418)
            eq_(write_args.get('error'), 'Test Failure')

        self.finish_deferred.addCallback(handle_finish)
        self.lch.get('CRIT')
        return self.finish_deferred
