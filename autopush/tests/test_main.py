import os
import unittest

import twisted.trial
import twisted.internet
from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_
from twisted.python import log

from autopush.main import connection_main, endpoint_main, unified_setup

mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class SentryLogTestCase(twisted.trial.unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        raven_patcher = patch("autopush.main.raven")
        self.mock_raven = raven_patcher.start()
        self.mock_client = Mock()
        self.mock_raven.Client.return_value = self.mock_client

    def tearDown(self):
        self.mock_raven.stop()

    def test_sentry_logging(self):
        os.environ["SENTRY_DSN"] = "some_locale"
        unified_setup()
        eq_(len(self.mock_raven.mock_calls), 2)

        log.err(Exception("eek"))
        self.flushLoggedErrors()
        eq_(len(self.mock_client.mock_calls), 1)


class ConnectionMainTestCase(unittest.TestCase):
    def setUp(self):
        patchers = [
            "autopush.main.log",
            "autopush.main.task",
            "autopush.main.reactor",
            "autopush.settings.TwistedStatsDClient",
        ]
        self.mocks = {}
        for name in patchers:
            patcher = patch(name)
            self.mocks[name] = patcher.start()

    def tearDown(self):
        for mock in self.mocks.values():
            mock.stop()

    def test_basic(self):
        connection_main([])


class EndpointMainTestCase(unittest.TestCase):
    def setUp(self):
        patchers = [
            "autopush.main.log",
            "autopush.main.task",
            "autopush.main.reactor",
            "autopush.settings.TwistedStatsDClient",
        ]
        self.mocks = {}
        for name in patchers:
            patcher = patch(name)
            self.mocks[name] = patcher.start()

    def tearDown(self):
        for mock in self.mocks.values():
            mock.stop()

    def test_basic(self):
        endpoint_main([])
