import unittest
import uuid

from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_

from autopush.main import (
    connection_main,
    endpoint_main,
    make_settings,
    skip_request_logging,
)
from autopush.utils import (
    str2bool,
    resolve_ip,
    generate_hash,
    validate_hash,
)
from autopush.settings import AutopushSettings


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class UtilsTestCase(unittest.TestCase):
    def test_str2bool(self):
        eq_(True, str2bool("t"))
        eq_(False, str2bool("false"))
        eq_(True, str2bool("True"))

    def test_validate_hash(self):
        key = str(uuid.uuid4())
        payload = str(uuid.uuid4())
        hashed = generate_hash(key, payload)
        print hashed

        eq_(validate_hash(key, payload, hashed), True)
        eq_(validate_hash(key, payload, str(uuid.uuid4())), False)
        eq_(validate_hash(key, payload, ""), False)


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
        patchers = [
            "autopush.main.task",
            "autopush.main.reactor",
            "autopush.main.listenWS",
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
    def setUp(self):
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

    def test_ping_settings(self):
        class arg:
            # important stuff
            external_router = True
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
            message_tablename = "None"
            message_read_throughput = 0
            message_write_throughput = 0

        ap = make_settings(arg)
        eq_(ap.routers["gcm"].gcm.api_key, arg.gcm_apikey)
        eq_(ap.routers["apns"].apns.cert_file, arg.apns_cert_file)
        eq_(ap.routers["apns"].apns.key_file, arg.apns_key_file)
