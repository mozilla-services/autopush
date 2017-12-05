import unittest
import datetime
import json

from mock import Mock, patch
import pytest
from twisted.internet.defer import Deferred
from twisted.trial import unittest as trialtest
import hyper
import hyper.tls

import autopush.db
from autopush.config import AutopushConfig
from autopush.db import DatabaseManager, get_rotating_message_table
from autopush.exceptions import InvalidConfig
from autopush.http import skip_request_logging
from autopush.main import (
    ConnectionApplication,
    EndpointApplication,
)
from autopush.tests.support import test_db
from autopush.utils import resolve_ip

connection_main = ConnectionApplication.main
endpoint_main = EndpointApplication.main


class ConfigTestCase(unittest.TestCase):
    def test_resolve_host(self):
        ip = resolve_ip("example.com")
        conf = AutopushConfig(
            hostname="example.com", resolve_hostname=True)
        assert conf.hostname == ip

    @patch("autopush.utils.socket")
    def test_resolve_host_no_interface(self, mock_socket):
        mock_socket.getaddrinfo.return_value = ""
        ip = resolve_ip("example.com")
        assert ip == "example.com"

    def test_new_month(self):
        today = datetime.date.today()
        next_month = today.month + 1
        next_year = today.year
        if next_month > 12:  # pragma: nocover
            next_month = 1
            next_year += 1
        tomorrow = datetime.datetime(year=next_year,
                                     month=next_month,
                                     day=1)
        db = test_db()
        db._tomorrow = Mock()
        db._tomorrow.return_value = tomorrow
        db.create_initial_message_tables()
        assert len(db.message_tables) == 3


class ConfigAsyncTestCase(trialtest.TestCase):
    def test_update_rotating_tables(self):
        from autopush.db import get_month
        conf = AutopushConfig(
            hostname="example.com", resolve_hostname=True)
        db = DatabaseManager.from_config(conf)
        db.create_initial_message_tables()

        # Erase the tables it has on init, and move current month back one
        last_month = get_month(-1)
        db.current_month = last_month.month
        db.message_tables = {}

        # Create the next month's table, just in case today is the day before
        # a new month, in which case the lack of keys will cause an error in
        # update_rotating_tables
        next_month = get_month(1)
        db.message_tables[next_month.month] = None

        # Get the deferred back
        e = Deferred()
        d = db.update_rotating_tables()

        def check_tables(result):
            assert len(db.message_tables) == 2
            assert db.current_month == get_month().month

        d.addCallback(check_tables)
        d.addBoth(lambda x: e.callback(True))
        return e

    def test_update_rotating_tables_month_end(self):
        """Test that rotating adds next months table

        This test is intended to ensure that if the next day is a new
        month, then update_rotating_tables realizes this and add's
        the new table to the message_tables.

        A pre-requisite is that today cannot be the last day of
        the current month. Therefore, we first sub in _tomorrow to
        ensure it always appears as next month, and then remove
        the new table create_initial_tables made so we can observe
        update_rotating_tables add the new one.

        Note that sorting message table keys to find the last month
        does *not work* since the month digit is not zero-padded.

        """
        today = datetime.date.today()
        next_month = today.month + 1
        next_year = today.year
        if next_month > 12:  # pragma: nocover
            next_month = 1
            next_year += 1
        tomorrow = datetime.datetime(year=next_year,
                                     month=next_month,
                                     day=1)

        conf = AutopushConfig(
            hostname="example.com", resolve_hostname=True)
        db = DatabaseManager.from_config(conf)
        db._tomorrow = Mock(return_value=tomorrow)
        db.create_initial_message_tables()

        # We should have 3 tables, one for next/this/last month
        assert len(db.message_tables) == 3

        # Grab next month's table name and remove it
        next_month = get_rotating_message_table(
            conf.message_table.tablename,
            delta=1
        )
        db.message_tables.pop(next_month.table_name)

        # Get the deferred back
        d = db.update_rotating_tables()

        def check_tables(result):
            assert len(db.message_tables) == 3
            assert next_month.table_name in db.message_tables

        d.addCallback(check_tables)
        return d

    def test_update_not_needed(self):
        from autopush.db import get_month
        conf = AutopushConfig(
            hostname="google.com", resolve_hostname=True)
        db = DatabaseManager.from_config(conf)
        db.create_initial_message_tables()

        # Erase the tables it has on init, and move current month back one
        db.message_tables = {}

        # Create the next month's table, just in case today is the day before
        # a new month, in which case the lack of keys will cause an error in
        # update_rotating_tables
        next_month = get_month(1)
        db.message_tables[next_month.month] = None

        # Get the deferred back
        e = Deferred()
        d = db.update_rotating_tables()

        def check_tables(result):
            assert len(db.message_tables) == 1

        d.addCallback(check_tables)
        d.addBoth(lambda x: e.callback(True))
        return e


class ConnectionMainTestCase(unittest.TestCase):
    def setUp(self):
        patchers = [
            "autopush.main.TimerService.startService",
            "autopush.main.reactor",
            "autopush.metrics.TwistedMetrics",
        ]
        self.mocks = {}
        for name in patchers:
            patcher = patch(name)
            self.mocks[name] = patcher.start()

    def tearDown(self):
        for mock in self.mocks.values():
            mock.stop()

    def test_basic(self):
        connection_main([], False)

    def test_basic_migration(self):
        connection_main([
            "--router_migrate_tablename=router_ttl"
        ], False)

    def test_ssl(self):
        connection_main([
            "--ssl_dh_param=keys/dhparam.pem",
            "--ssl_cert=keys/server.crt",
            "--ssl_key=keys/server.key",
            "--router_ssl_cert=keys/server.crt",
            "--router_ssl_key=keys/server.key",
        ], False)

    def test_memusage(self):
        connection_main([
            "--memusage_port=8083",
        ], False)

    def test_skip_logging(self):
        # Should skip setting up logging on the handler
        mock_handler = Mock()
        skip_request_logging(mock_handler)
        assert len(mock_handler.mock_calls) == 0


class EndpointMainTestCase(unittest.TestCase):
    class TestArg(AutopushConfig):
        # important stuff
        apns_creds = json.dumps({"firefox": {"cert": "cert.file",
                                             "key": "key.file"}})
        gcm_enabled = True
        # less important stuff
        gcm_ttl = 999
        gcm_dryrun = False
        gcm_collapsekey = "collapse"
        max_data = 4096
        # filler
        crypto_key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        datadog_api_key = "datadog_api_key"
        datadog_app_key = "datadog_app_key"
        datadog_flush_interval = "datadog_flush_interval"
        hostname = "hostname"
        statsd_host = "statsd_host"
        statsd_port = "statsd_port"
        router_tablename = "none"
        router_read_throughput = 0
        router_write_throughput = 0
        router_migrate_tablename = None
        resolve_hostname = False
        message_tablename = "None"
        message_read_throughput = 0
        message_write_throughput = 0
        senderid_list = '{"12345":{"auth":"abcd"}}'
        key_hash = "supersikkret"
        no_aws = True
        fcm_enabled = True
        fcm_ttl = 999
        fcm_dryrun = False
        fcm_collapsekey = "collapse"
        fcm_senderid = '12345'
        fcm_auth = 'abcde'
        ssl_key = "keys/server.crt"
        ssl_cert = "keys/server.key"
        ssl_dh_param = None
        msg_limit = 1000
        _client_certs = dict(partner1=["1A:"*31 + "F9"],
                             partner2=["2B:"*31 + "E8",
                                       "3C:"*31 + "D7"])
        client_certs = json.dumps(_client_certs)
        connection_timeout = 1

        proxy_protocol_port = None
        memusage_port = None
        disable_simplepush = True
        use_cryptography = False
        sts_max_age = 1234
        _no_sslcontext_cache = False

    def setUp(self):
        patchers = [
            "autopush.db.preflight_check",
            "autopush.main.TimerService.startService",
            "autopush.main.reactor",
            "autopush.metrics.TwistedMetrics",
        ]
        self.mocks = {}
        for name in patchers:
            patcher = patch(name)
            self.mocks[name] = patcher.start()

    def tearDown(self):
        for mock in self.mocks.values():
            mock.stop()
        autopush.db.key_hash = ""

    def test_basic(self):
        endpoint_main([
        ], False)

    def test_ssl(self):
        endpoint_main([
            "--ssl_dh_param=keys/dhparam.pem",
            "--ssl_cert=keys/server.crt",
            "--ssl_key=keys/server.key",
        ], False)

    def test_bad_senderidlist(self):
        returncode = endpoint_main([
            "--gcm_enabled",
            "--senderid_list='[Invalid'"
        ], False)
        assert returncode not in (None, 0)

    def test_bad_apnsconf(self):
        returncode = endpoint_main([
            "--apns_creds='[Invalid'"
        ], False)
        assert returncode not in (None, 0)

    def test_client_certs(self):
        cert = self.TestArg._client_certs['partner1'][0]
        returncode = endpoint_main([
            "--ssl_cert=keys/server.crt",
            "--ssl_key=keys/server.key",
            '--client_certs={"foo": ["%s"]}' % cert
        ], False)
        assert not returncode

    def test_proxy_protocol_port(self):
        endpoint_main([
            "--proxy_protocol_port=8081",
        ], False)

    def test_memusage(self):
        endpoint_main([
            "--memusage_port=8083",
        ], False)

    def test_client_certs_parse(self):
        conf = AutopushConfig.from_argparse(self.TestArg)
        assert conf.client_certs["1A:"*31 + "F9"] == 'partner1'
        assert conf.client_certs["2B:"*31 + "E8"] == 'partner2'
        assert conf.client_certs["3C:"*31 + "D7"] == 'partner2'

    def test_bad_client_certs(self):
        cert = self.TestArg._client_certs['partner1'][0]
        ssl_opts = ["--ssl_cert=keys/server.crt", "--ssl_key=keys/server.key"]
        assert endpoint_main(
            ssl_opts + ["--client_certs='[Invalid'"], False) == 1
        assert endpoint_main(
            ssl_opts + ['--client_certs={"": ["%s"]}' % cert], False) == 1
        assert endpoint_main(
            ssl_opts + ['--client_certs={"quux": [""]}'], False) == 1
        assert endpoint_main(
            ssl_opts + ['--client_certs={"foo": "%s"}' % cert], False) == 1
        assert endpoint_main(
            ['--client_certs={"foo": ["%s"]}' % cert], False) == 1

    @patch('autopush.router.apns2.HTTP20Connection',
           spec=hyper.HTTP20Connection)
    @patch('hyper.tls', spec=hyper.tls)
    def test_conf(self, *args):
        conf = AutopushConfig.from_argparse(self.TestArg)
        app = EndpointApplication(conf)
        # verify that the hostname is what we said.
        assert conf.hostname == self.TestArg.hostname
        assert app.routers["gcm"].router_conf['collapsekey'] == "collapse"
        assert app.routers["apns"].router_conf['firefox']['cert'] == \
            "cert.file"
        assert app.routers["apns"].router_conf['firefox']['key'] == "key.file"

    def test_bad_senders(self):
        old_list = self.TestArg.senderid_list
        self.TestArg.senderid_list = "{}"
        with pytest.raises(InvalidConfig):
            AutopushConfig.from_argparse(self.TestArg)
        self.TestArg.senderid_list = old_list

    def test_bad_fcm_senders(self):
        old_auth = self.TestArg.fcm_auth
        old_senderid = self.TestArg.fcm_senderid
        self.TestArg.fcm_auth = ""
        with pytest.raises(InvalidConfig):
            AutopushConfig.from_argparse(self.TestArg)
        self.TestArg.fcm_auth = old_auth
        self.TestArg.fcm_senderid = ""
        with pytest.raises(InvalidConfig):
            AutopushConfig.from_argparse(self.TestArg)
        self.TestArg.fcm_senderid = old_senderid

    def test_gcm_start(self):
        endpoint_main([
            "--gcm_enabled",
            """--senderid_list={"123":{"auth":"abcd"}}""",
        ], False)

    @patch("requests.get")
    def test_aws_ami_id(self, request_mock):
        class MockReply:
            content = "ami_123"

        request_mock.return_value = MockReply
        self.TestArg.no_aws = False
        conf = AutopushConfig.from_argparse(self.TestArg)
        assert conf.ami_id == "ami_123"

    def test_no_sslcontext_cache(self):
        conf = AutopushConfig.from_argparse(self.TestArg)
        assert not conf.no_sslcontext_cache
        self.TestArg._no_sslcontext_cache = True
        conf = AutopushConfig.from_argparse(self.TestArg)
        assert conf.no_sslcontext_cache
