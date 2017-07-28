import json

import twisted.internet.base
from boto.dynamodb2.exceptions import InternalServerError
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_
from twisted.internet.defer import inlineCallbacks
from twisted.logger import globalLogPublisher
from twisted.trial import unittest

from autopush import __version__
from autopush.db import DatabaseManager
from autopush.exceptions import MissingTableException
from autopush.http import EndpointHTTPFactory
from autopush.logging import begin_or_register
from autopush.settings import AutopushSettings
from autopush.tests.client import Client
from autopush.tests.support import TestingLogObserver
from autopush.web.health import HealthHandler, StatusHandler


class HealthTestCase(unittest.TestCase):
    def setUp(self):
        self.timeout = 0.5
        twisted.internet.base.DelayedCall.debug = True

        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()
        self.addCleanup(self.mock_dynamodb2.stop)

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        db = DatabaseManager.from_settings(settings)
        db.setup_tables()

        # ignore logging
        logs = TestingLogObserver()
        begin_or_register(logs)
        self.addCleanup(globalLogPublisher.removeObserver, logs)

        app = EndpointHTTPFactory.for_handler(HealthHandler, settings, db=db)
        self.router_table = app.db.router.table
        self.storage_table = app.db.storage.table
        self.client = Client(app)

    @inlineCallbacks
    def test_healthy(self):
        yield self._assert_reply({
            "status": "OK",
            "version": __version__,
            "clients": 0,
            "storage": {"status": "OK"},
            "router": {"status": "OK"}
        })

    @inlineCallbacks
    def test_aws_error(self):
        def raise_error(*args, **kwargs):
            raise InternalServerError(None, None)
        self.router_table.connection.list_tables = Mock(
            side_effect=raise_error)
        self.storage_table.connection.list_tables = Mock(
            return_value={"TableNames": ["storage"]})

        yield self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "storage": {"status": "OK"},
            "router": {
                "status": "NOT OK",
                "error": "Server error"
            }
        }, InternalServerError)

    @inlineCallbacks
    def test_nonexistent_table(self):
        no_tables = Mock(return_value={"TableNames": []})
        self.storage_table.connection.list_tables = no_tables
        self.router_table.connection.list_tables = no_tables

        yield self._assert_reply({
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

    @inlineCallbacks
    def test_internal_error(self):
        def raise_error(*args, **kwargs):
            raise Exception("synergies not aligned")
        self.router_table.connection.list_tables = Mock(
            return_value={"TableNames": ["router"]})
        self.storage_table.connection.list_tables = Mock(
            side_effect=raise_error)

        yield self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "storage": {
                "status": "NOT OK",
                "error": "Internal error"
            },
            "router": {"status": "OK"}
        }, Exception)

    @inlineCallbacks
    def _assert_reply(self, reply, exception=None):
        resp = yield self.client.get('/health')
        if exception:
            eq_(resp.get_status(), 503)
            self.flushLoggedErrors(exception)
        payload = json.loads(resp.content)
        eq_(payload, reply)


class StatusTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.request_mock = Mock()
        self.status = StatusHandler(
            EndpointHTTPFactory(settings, db=None, routers=None),
            self.request_mock
        )
        self.write_mock = self.status.write = Mock()

    def test_status(self):
        self.status.get()
        self.write_mock.assert_called_with({
            "status": "OK",
            "version": __version__
        })
