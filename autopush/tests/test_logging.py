import os

import twisted.internet
import twisted.trial

from mock import Mock, patch
from nose.tools import eq_
from twisted.python import log

from autopush.logging import setup_logging


class SentryLogTestCase(twisted.trial.unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        raven_patcher = patch("autopush.logging.raven")
        self.mock_raven = raven_patcher.start()
        self.mock_client = Mock()
        self.mock_raven.Client.return_value = self.mock_client

    def tearDown(self):
        self.mock_raven.stop()

    def test_sentry_logging(self):
        os.environ["SENTRY_DSN"] = "some_locale"
        setup_logging("Autopush")
        eq_(len(self.mock_raven.mock_calls), 2)

        log.err(Exception("eek"))
        self.flushLoggedErrors()
        eq_(len(self.mock_client.mock_calls), 1)
