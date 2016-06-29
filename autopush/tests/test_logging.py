import json
import os

import cyclone.web
import twisted.internet
import twisted.trial.unittest

from mock import Mock, patch
from nose.tools import eq_, ok_
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.logger import Logger
from twisted.python import failure

from autopush.logging import PushLogger, FirehoseProcessor

log = Logger()


class LocalSentryChomper(cyclone.web.RequestHandler):
    def post(self):
        self.logged.append(json.loads(self.request.body.decode("zlib")))
        return ""


class SentryLogTestCase(twisted.trial.unittest.TestCase):
    def setUp(self):
        from autopush.main import skip_request_logging
        twisted.internet.base.DelayedCall.debug = True
        sentry = LocalSentryChomper
        sentry.logged = []
        site = cyclone.web.Application([
            (r"/.*", sentry),
        ],
            log_function=skip_request_logging
        )
        self.sentry = sentry
        self._site = site
        self._port = reactor.listenTCP(9999, site)

    def tearDown(self):
        reactor.removeAll()

    def test_sentry_logging(self):
        dsn = "http://PUBKEY:SECKEY@localhost:9999/1"
        os.environ["SENTRY_DSN"] = dsn
        pl = PushLogger.setup_logging("Autopush", sentry_dsn=True)

        log.failure("error", failure.Failure(Exception("eek")))
        self.flushLoggedErrors()
        d = Deferred()

        def check():
            if len(self.sentry.logged):
                eq_(len(self.sentry.logged), 1)
                self._port.stopListening()
                pl.stop()
                d.callback(True)
            else:  # pragma: nocover
                reactor.callLater(0, check)
        del os.environ["SENTRY_DSN"]
        reactor.callLater(0, check)
        return d


class PushLoggerTestCase(twisted.trial.unittest.TestCase):
    def test_custom_type(self):
        obj = PushLogger.setup_logging("Autopush")
        obj._output = mock_stdout = Mock()
        log.info("omg!", Type=7)
        eq_(len(mock_stdout.mock_calls), 2)
        kwargs = mock_stdout.mock_calls[0][1][0]
        ok_("Type" in kwargs)

    def test_human_logs(self):
        obj = PushLogger.setup_logging("Autopush", log_format="text")
        obj._output = mock_stdout = Mock()
        log.info("omg!", Type=7)
        eq_(len(mock_stdout.mock_calls), 2)
        mock_stdout.reset_mock()
        log.error("wtf!", Type=7)
        eq_(len(mock_stdout.mock_calls), 2)

    def test_start_stop(self):
        obj = PushLogger.setup_logging("Autopush")
        obj.start()
        obj.stop()

    def test_file_output(self):
        try:
            os.unlink("testfile.txt")
        except:  # pragma: nocover
            pass
        obj = PushLogger.setup_logging("Autoput", log_output="testfile.txt")
        obj.start()
        log.info("wow")
        obj.stop()
        with open("testfile.txt") as f:
            lines = f.readlines()
        eq_(len(lines), 1)

    @patch("autopush.logging.boto3")
    def test_firehose_only_output(self, mock_boto3):
        obj = PushLogger("Autoput", log_output="none",
                         firehose_delivery_stream="test")
        obj.firehose = Mock(spec=FirehoseProcessor)
        obj.start()
        log.info("wow")
        obj.stop()
        eq_(len(obj.firehose.mock_calls), 3)
        eq_(len(obj.firehose.process.mock_calls), 1)


class FirehoseProcessorTestCase(twisted.trial.unittest.TestCase):
    def setUp(self):
        patcher = patch("autopush.logging.boto3")
        self.patcher = patcher
        self.mock_boto = patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_full_queue(self):
        proc = FirehoseProcessor("test", 1)
        proc.process("test")
        eq_(proc._records.full(), True)
        proc.process("another")
        eq_(proc._records.qsize(), 1)
        eq_(proc._records.get(), "test")

    def test_message_max_size(self):
        proc = FirehoseProcessor("test")
        proc.MAX_REQUEST_SIZE = 1

        # Setup the mock
        proc._client.put_record_batch.return_value = dict(FailedPutCount=0)

        # Start and log
        proc.start()
        proc.process("a decently larger message")
        proc.stop()
        eq_(len(self.mock_boto.mock_calls), 2)
        eq_(len(proc._client.put_record_batch.mock_calls), 1)

    def test_message_max_batch(self):
        proc = FirehoseProcessor("test")
        proc.MAX_RECORD_BATCH = 1

        # Setup the mock
        proc._client.put_record_batch.return_value = dict(FailedPutCount=0)

        # Start and log
        proc.start()
        proc.process("a decently larger message")
        proc.stop()
        eq_(len(self.mock_boto.mock_calls), 2)
        eq_(len(proc._client.put_record_batch.mock_calls), 1)

    def test_queue_timeout(self):
        proc = FirehoseProcessor("test")
        proc.MAX_INTERVAL = 0

        proc.start()
        proc.stop()
        eq_(len(self.mock_boto.mock_calls), 1)

    def test_batch_send_failure(self):
        proc = FirehoseProcessor("test")
        proc.MAX_RECORD_BATCH = 1

        # Setup the mock
        proc._client.put_record_batch.return_value = dict(FailedPutCount=1)

        # Start and log
        proc.start()
        proc.process("a decently larger message")
        proc.stop()
        eq_(len(self.mock_boto.mock_calls), 4)
        eq_(len(proc._client.put_record_batch.mock_calls), 3)
