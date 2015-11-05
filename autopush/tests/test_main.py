import unittest

from mock import Mock, patch
from moto import mock_dynamodb2, mock_s3
from nose.tools import eq_

from autopush.main import (
    connection_main,
    endpoint_main,
    make_settings,
    skip_request_logging,
)
from autopush.utils import (
    resolve_ip,
)
from autopush.settings import AutopushSettings


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()
    mock_s3().start()


def tearDown():
    mock_dynamodb2.stop()
    mock_s3().stop()


class SettingsTestCase(unittest.TestCase):
    def test_resolve_host(self):
        ip = resolve_ip("google.com")
        settings = AutopushSettings(
            hostname="google.com", resolve_hostname=True)
        eq_(settings.hostname, ip)

    @patch("autopush.utils.socket")
    def test_resolve_host_no_interface(self, mock_socket):
        mock_socket.getaddrinfo.return_value = ""
        ip = resolve_ip("google.com")
        eq_(ip, "google.com")


class ConnectionMainTestCase(unittest.TestCase):
    def setUp(self):
        mock_s3().start()
        patchers = [
            "autopush.main.task",
            "autopush.main.reactor",
            "autopush.settings.TwistedMetrics",
        ]
        self.mocks = {}
        for name in patchers:
            patcher = patch(name)
            self.mocks[name] = patcher.start()

    def tearDown(self):
        mock_s3().stop()
        for mock in self.mocks.values():
            mock.stop()

    def test_basic(self):
        connection_main([])

    def test_ssl(self):
        connection_main([
            "--ssl_dh_param=keys/dhparam.pem",
            "--ssl_cert=keys/server.crt",
            "--ssl_key=keys/server.key",
            "--router_ssl_cert=keys/server.crt",
            "--router_ssl_key=keys/server.key",
        ])

    def test_skip_logging(self):
        # Should skip setting up logging on the handler
        mock_handler = Mock()
        skip_request_logging(mock_handler)
        eq_(len(mock_handler.mock_calls), 0)


class EndpointMainTestCase(unittest.TestCase):
    class test_arg:
        # important stuff
        external_router = True
        apns_cert_file = "cert.file"
        apns_key_file = "key.file"
        gcm_enabled = True
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
        # UDP
        wake_pem = "test"
        wake_timeout = 10
        wake_server = "http://example.com"
        message_tablename = "None"
        message_read_throughput = 0
        message_write_throughput = 0
        senderid_list = '{"12345":{"auth":"abcd"}}'
        s3_bucket = "None"
        senderid_expry = 0

    def setUp(self):
        mock_s3().start()
        patchers = [
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
        mock_s3().stop()
        for mock in self.mocks.values():
            mock.stop()

    def test_basic(self):
        endpoint_main([])

    def test_ssl(self):
        endpoint_main([
            "--ssl_dh_param=keys/dhparam.pem",
            "--ssl_cert=keys/server.crt",
            "--ssl_key=keys/server.key",
        ])

    def test_bad_senderidlist(self):
        endpoint_main([
            "--senderid_list='[Invalid'"
        ])

    def test_ping_settings(self):
        ap = make_settings(self.test_arg)
        # verify that the hostname is what we said.
        eq_(ap.hostname, self.test_arg.hostname)
        # gcm isn't created until later since we may have to pull
        # config info from s3
        eq_(ap.routers["apns"].apns.cert_file, self.test_arg.apns_cert_file)
        eq_(ap.routers["apns"].apns.key_file, self.test_arg.apns_key_file)
        eq_(ap.wake_timeout, 10)

    def test_bad_senders(self):
        oldList = self.test_arg.senderid_list
        self.test_arg.senderid_list = "{}"
        ap = make_settings(self.test_arg)
        eq_(ap, None)
        self.test_arg.senderid_list = oldList
