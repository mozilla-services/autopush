import unittest

from mock import patch
from moto import mock_dynamodb2
from nose.tools import eq_

from autopush.main import (
    connection_main,
    endpoint_main,
    unified_main,
    make_settings
)
from autopush.endpoint import (EndpointHandler, RegistrationHandler)
from autopush.websocket import (
    SimplePushServerProtocol,
    RouterHandler,
    NotificationHandler,
)

mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class UnifiedMainTestCase(unittest.TestCase):
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
        unified_main([
            "--hostname",
            "localhost",
        ])
        eq_(len(self.mocks["autopush.main.reactor"].run.mock_calls), 1)
        # Should use a unified settings object for all handlers.
        settings = EndpointHandler.ap_settings
        eq_(settings, RegistrationHandler.ap_settings)
        eq_(settings, SimplePushServerProtocol.ap_settings)
        eq_(settings, RouterHandler.ap_settings)
        eq_(settings, NotificationHandler.ap_settings)
        eq_(settings.connection_hostname, "localhost")
        eq_(settings.connection_port, 8080)
        eq_(settings.endpoint_url, "http://localhost:8082")
        eq_(settings.router_url, "http://localhost:8081")


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
