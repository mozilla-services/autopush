import json

import twisted.internet.base
from boto.dynamodb2.exceptions import InternalServerError
from mock import Mock
from twisted.internet.defer import inlineCallbacks
from twisted.logger import globalLogPublisher
from twisted.trial import unittest

import autopush.db
from autopush import __version__
from autopush.config import AutopushConfig
from autopush.db import DatabaseManager
from autopush.exceptions import MissingTableException
from autopush.http import EndpointHTTPFactory
from autopush.logging import begin_or_register
from autopush.tests.client import Client
from autopush.tests.support import TestingLogObserver
from autopush.web.health import HealthHandler, StatusHandler


class HealthTestCase(unittest.TestCase):
    def setUp(self):
        self.timeout = 0.5
        twisted.internet.base.DelayedCall.debug = True

        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )

        db = DatabaseManager.from_config(conf)
        db.client = autopush.db.g_client
        db.setup_tables()

        # ignore logging
        logs = TestingLogObserver()
        begin_or_register(logs)
        self.addCleanup(globalLogPublisher.removeObserver, logs)

        app = EndpointHTTPFactory.for_handler(HealthHandler, conf, db=db)
        self.router_table = app.db.router.table
        self.message = app.db.message
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

        safe = self.client.app.db.client
        self.client.app.db.client = Mock()
        self.client.app.db.client.list_tables = Mock(side_effect=raise_error)

        yield self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "storage": {
                "status": "NOT OK",
                "error": "Server error"
            },
            "router": {
                "status": "NOT OK",
                "error": "Server error"
            }
        }, InternalServerError)

        self.client.app.db.client = safe

    @inlineCallbacks
    def test_nonexistent_table(self):
        no_tables = Mock(return_value={"TableNames": []})
        safe = self.client.app.db.client
        self.client.app.db.client = Mock()
        self.client.app.db.client.list_tables = no_tables

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
        self.client.app.db.client = safe

    @inlineCallbacks
    def test_internal_error(self):
        def raise_error(*args, **kwargs):
            raise Exception("synergies not aligned")

        safe = self.client.app.db.client
        self.client.app.db.client = Mock()
        self.client.app.db.client.list_tables = Mock(
            side_effect=raise_error
        )

        yield self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "storage": {
                "status": "NOT OK",
                "error": "Internal error"
            },
            "router": {
                "status": "NOT OK",
                "error": "Internal error"
            }
        }, Exception)
        self.client.app.db.client = safe

    @inlineCallbacks
    def _assert_reply(self, reply, exception=None):
        resp = yield self.client.get('/health')
        if exception:
            assert resp.get_status() == 503
            self.flushLoggedErrors(exception)
        payload = json.loads(resp.content)
        assert payload == reply


class StatusTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.request_mock = Mock()
        self.status = StatusHandler(
            EndpointHTTPFactory(conf, db=None, routers=None),
            self.request_mock
        )
        self.write_mock = self.status.write = Mock()

    def test_status(self):
        self.status.get()
        self.write_mock.assert_called_with({
            "status": "OK",
            "version": __version__
        })
