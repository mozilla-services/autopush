import json

import twisted
from twisted.internet.defer import inlineCallbacks
from twisted.logger import globalLogPublisher
from twisted.trial import unittest

from autopush.config import AutopushConfig
from autopush.http import EndpointHTTPFactory
from autopush.logging import begin_or_register
from autopush.tests.client import Client
from autopush.tests.support import TestingLogObserver
from autopush.web.log_check import LogCheckHandler


class LogCheckTestCase(unittest.TestCase):

    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True

        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )

        self.logs = TestingLogObserver()
        begin_or_register(self.logs, discardBuffer=True)
        self.addCleanup(globalLogPublisher.removeObserver, self.logs)

        app = EndpointHTTPFactory.for_handler(LogCheckHandler, conf)
        self.client = Client(app)

    @inlineCallbacks
    def test_get_err(self):
        resp = yield self.client.get('/v1/err')
        assert len(self.logs) == 2
        assert self.logs.logged(
            lambda e: (e['log_level'].name == 'error' and
                       e['log_format'] == 'Test Error Message' and
                       e['status_code'] == 418)
        )
        payload = json.loads(resp.content)
        assert payload.get('code') == 418
        assert payload.get('message') == "ERROR:Success"

    @inlineCallbacks
    def test_get_crit(self):
        resp = yield self.client.get('/v1/err/crit')
        assert len(self.logs) == 2
        assert self.logs.logged(
            lambda e: (e['log_level'].name == 'critical' and
                       e['log_failure'] and
                       e['log_format'] == 'Test Critical Message' and
                       e['status_code'] == 418)
        )
        payload = json.loads(resp.content)
        assert payload.get('code') == 418
        assert payload.get('error') == "Test Failure"

        self.flushLoggedErrors()
