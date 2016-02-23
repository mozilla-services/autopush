import os

import twisted.internet
import twisted.trial.unittest

from mock import Mock, patch
from nose.tools import eq_, ok_
from twisted.python import log, failure

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

        log.err(failure.Failure(Exception("eek")))
        self.flushLoggedErrors()
        eq_(len(self.mock_client.mock_calls), 1)
        del os.environ["SENTRY_DSN"]


class EliotLogTestCase(twisted.trial.unittest.TestCase):
    def test_custom_type(self):
        setup_logging("Autopush")
        with patch("sys.stdout") as mock_stdout:
            log.msg("omg!", Type=7)
            eq_(len(mock_stdout.mock_calls), 1)
            kwargs = mock_stdout.mock_calls[0][1][0]
        ok_("Type" in kwargs)

    def test_human_logs(self):
        setup_logging("Autopush", True)
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.reset_mock()
            log.msg("omg!", Type=7)
            eq_(len(mock_stdout.mock_calls), 4)
            mock_stdout.reset_mock()
            log.err("wtf!", Type=7)
            eq_(len(mock_stdout.mock_calls), 4)
