import twisted.internet.base

from boto.dynamodb2.exceptions import (
    InternalServerError,
)
from cyclone.web import Application
from mock import Mock
from moto import mock_dynamodb2
from twisted.internet.defer import Deferred
from twisted.trial import unittest

from autopush import __version__
from autopush.health import (
    HealthHandler,
    MissingTableException,
    StatusHandler,
)
from autopush.settings import AutopushSettings


class HealthTestCase(unittest.TestCase):
    def setUp(self):
        from twisted.logger import Logger
        self.timeout = 0.5
        twisted.internet.base.DelayedCall.debug = True

        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()

        ap_settings = self.settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.router_table = self.settings.router.table
        self.storage_table = self.settings.storage.table

        self.request_mock = Mock()
        self.health = HealthHandler(Application(),
                                    self.request_mock,
                                    ap_settings=ap_settings)
        self.health.log = self.log_mock = Mock(spec=Logger)
        self.status_mock = self.health.set_status = Mock()
        self.write_mock = self.health.write = Mock()

        d = self.finish_deferred = Deferred()
        self.health.finish = lambda: d.callback(True)

    def tearDown(self):
        self.mock_dynamodb2.stop()

    def test_healthy(self):
        return self._assert_reply({
            "status": "OK",
            "version": __version__,
            "clients": 0,
            "storage": {"status": "OK"},
            "router": {"status": "OK"}
        })

    def test_aws_error(self):
        def raise_error(*args, **kwargs):
            raise InternalServerError(None, None)
        self.router_table.connection.list_tables = Mock(
            side_effect=raise_error)
        self.storage_table.connection.list_tables = Mock(
            return_value={"TableNames": ["storage"]})

        return self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "storage": {"status": "OK"},
            "router": {
                "status": "NOT OK",
                "error": "Server error"
            }
        }, InternalServerError)

    def test_nonexistent_table(self):
        no_tables = Mock(return_value={"TableNames": []})
        self.storage_table.connection.list_tables = no_tables
        self.router_table.connection.list_tables = no_tables

        return self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "storage": {
                "status": "NOT OK",
                "error": "Nonexistent table"
            },
            "router": {
                "status": "NOT OK",
                "error": "Nonexistent table"
            }
        }, MissingTableException)

    def test_internal_error(self):
        def raise_error(*args, **kwargs):
            raise Exception("synergies not aligned")
        self.router_table.connection.list_tables = Mock(
            return_value={"TableNames": ["router"]})
        self.storage_table.connection.list_tables = Mock(
            side_effect=raise_error)

        return self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "storage": {
                "status": "NOT OK",
                "error": "Internal error"
            },
            "router": {"status": "OK"}
        }, Exception)

    def _assert_reply(self, reply, exception=None):
        def handle_finish(result):
            if exception:
                self.status_mock.assert_called_with(503)
                self.flushLoggedErrors(exception)
            self.write_mock.assert_called_with(reply)
        self.finish_deferred.addCallback(handle_finish)

        self.health.get()
        return self.finish_deferred


class StatusTestCase(unittest.TestCase):
    def setUp(self):
        self.timeout = 0.5
        twisted.internet.base.DelayedCall.debug = True

        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()

        self.settings = StatusHandler.ap_settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.request_mock = Mock()
        self.status = StatusHandler(Application(), self.request_mock)
        self.write_mock = self.status.write = Mock()

    def tearDown(self):
        self.mock_dynamodb2.stop()

    def test_status(self):
        self.status.get()
        self.write_mock.assert_called_with({
            "status": "OK",
            "version": __version__
        })
