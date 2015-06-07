import unittest

from mock import patch
from moto import mock_dynamodb2
from nose.tools import eq_

from autopush.main import (
    connection_main,
    endpoint_main,
    make_settings
)

mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


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
            "autopush.settings.preflight_check",
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
            bridge = True
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
            resolve_hostname = False

        ap = make_settings(arg)
        eq_(ap.routers["gcm"].gcm.api_key, arg.gcm_apikey)
        eq_(ap.routers["apns"].apns.cert_file, arg.apns_cert_file)
        eq_(ap.routers["apns"].apns.key_file, arg.apns_key_file)
