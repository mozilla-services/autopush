import json

import pytest
import twisted.internet.base
from mock import Mock, patch
from twisted.internet.defer import inlineCallbacks
from twisted.logger import globalLogPublisher
from twisted.trial import unittest

from autopush import __version__
from autopush.config import AutopushConfig, DDBTableConfig
from autopush.db import DatabaseManager
from autopush.exceptions import MissingTableException
from autopush.http import EndpointHTTPFactory
from autopush.logging import begin_or_register
from autopush.tests.client import Client
from autopush.tests.support import TestingLogObserver
from autopush.web.health import HealthHandler, StatusHandler
from autopush.web.dockerflow import LBHeartbeatHandler, VersionHandler
import autopush.tests


class HealthTestCase(unittest.TestCase):
    def setUp(self):
        self.timeout = 4
        twisted.internet.base.DelayedCall.debug = True

        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
            router_table=DDBTableConfig(tablename="router_test"),
            message_table=DDBTableConfig(tablename="message_int_test"),
        )

        db = DatabaseManager.from_config(
            conf,
            resource=autopush.tests.boto_resource)
        db.setup_tables()

        # ignore logging
        logs = TestingLogObserver()
        begin_or_register(logs)
        self.addCleanup(globalLogPublisher.removeObserver, logs)

        app = EndpointHTTPFactory.for_handler(HealthHandler, conf, db=db)
        self.message = app.db.message
        self.client = Client(app)

    @inlineCallbacks
    def test_healthy(self):
        yield self._assert_reply({
            "status": "OK",
            "version": __version__,
            "clients": 0,
            "storage": {"status": "OK"},
            "router_test": {"status": "OK"}
        })

    @inlineCallbacks
    def test_nonexistent_table(self):
        self.client.app.db.message.table.delete()

        yield self._assert_reply({
            "status": "NOT OK",
            "version": __version__,
            "clients": 0,
            "router_test": {"status": "OK"},
            "storage": {
                "status": "NOT OK",
                "error": "Nonexistent table"
            }
        }, MissingTableException)

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


class DockerflowTestCase(unittest.TestCase):
    def setUp(self):
        self.timeout = 4
        twisted.internet.base.DelayedCall.debug = True

        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )

        # ignore logging
        logs = TestingLogObserver()
        begin_or_register(logs)
        self.addCleanup(globalLogPublisher.removeObserver, logs)

        lb_app = EndpointHTTPFactory.for_handler(
            LBHeartbeatHandler, conf, db=None
        )
        ver_app = EndpointHTTPFactory.for_handler(
            VersionHandler, conf, db=None
        )
        self.lb_client = Client(lb_app)
        self.ver_client = Client(ver_app)

    @inlineCallbacks
    def test_lbheartbeat(self):
        resp = yield self.lb_client.get("/__lbheartbeat__")
        assert resp.get_status() == 200

    @patch('autopush.web.dockerflow.open')
    def test_version(self, mopen):
        version = """{
  "source" : "https://github.com/mozilla-services/autopush",
  "version": "devel",
  "commit" : "",
  "build"  : ""
}
"""
        reader = Mock()
        reader.read.return_value = version
        mopen.__enter__.return_value = reader
        mopen.return_value = mopen
        resp = yield self.ver_client.get("/__version__")
        assert resp.get_status() == 200
        assert resp.content == version

    @patch('autopush.web.dockerflow.open')
    def test_bad_version(self, mopen):
        reader = Mock()
        reader.read.side_effect = IOError
        mopen.__enter__.return_value = reader
        mopen.return_value = mopen
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.request_mock = Mock()
        bad_ver = VersionHandler(
            EndpointHTTPFactory(conf, db=None, routers=None),
            self.request_mock
        )
        with pytest.raises(IOError):
            bad_ver._get_version()
