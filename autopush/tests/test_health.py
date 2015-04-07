import twisted.internet.base

from cyclone.web import Application
from mock import Mock
from moto import mock_dynamodb2
from twisted.trial import unittest

from autopush import __version__
from autopush.health import StatusHandler
from autopush.settings import AutopushSettings


class HealthTestCase(unittest.TestCase):
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
