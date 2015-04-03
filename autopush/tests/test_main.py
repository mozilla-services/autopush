import os
import unittest

import twisted.trial
import twisted.internet
from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_
from twisted.python import log

from autopush.main import (
    connection_main, endpoint_main, unified_setup, make_settings
)

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
            "autopush.settings.TwistedMetrics",
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
            "autopush.settings.TwistedMetrics",
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

    def test_ping_settings(self):
        class arg:
            # important stuff
            pinger = True
            gcm_apikey = "gcm.key"
            apns_cert_file = "cert.file"
            apns_key_file = "key.file"
            # less important stuff
            apns_sandbox = False
            gcm_ttl = 999
            gcm_dryrun = False
            gcm_collapsekey = "collapse"

            # filler
            crypto_key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
            datadog_api_key = "datadog_api_key"
            datadog_app_key = "datadog_app_key"
            datadog_flush_interval = "datadog_flush_interval"
            hostname = "hostname"
            statsd_host = "statsd_host"
            statsd_port = "statsd_port"
            router_tablename = "None"
            storage_tablename = "None"
            storage_read_throughput = 0
            storage_write_throughput = 0
            router_read_throughput = 0
            router_write_throughput = 0

        ap = make_settings(arg)
        eq_(ap.pinger.gcm.gcm.api_key, arg.gcm_apikey)
        eq_(ap.pinger.apns.apns.cert_file, arg.apns_cert_file)
        eq_(ap.pinger.apns.apns.key_file, arg.apns_key_file)
