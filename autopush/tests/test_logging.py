import json
import os
import Queue
import sys
import StringIO

import cyclone.web
import twisted.internet
import twisted.trial.unittest

from mock import Mock, patch
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
        from autopush.http import skip_request_logging
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
        os.environ["SENTRY_DSN"] = "http://PUBKEY:SECKEY@localhost:9999/1"

    def tearDown(self):
        os.environ.pop("SENTRY_DSN", None)
        reactor.removeAll()

    def test_sentry_logging(self):
        out = StringIO.StringIO()
        pl = PushLogger.setup_logging("Autopush", sentry_dsn=True)
        pl._output = out
        _client_info = dict(key='value')
        _timings = dict(key2='value', key3=True)

        log.failure(format="error",
                    failure=failure.Failure(Exception("eek")),
                    client_info=_client_info,
                    timings=_timings)
        self.flushLoggedErrors()
        d = Deferred()

        def check():
            logged = self.sentry.logged
            if not logged:   # pragma: nocover
                reactor.callLater(0, check)
                return
            assert len(logged) == 1
            # Check that the sentry data has the client info as a sub dict
            # Note: these are double quoted, single quote strings.
            assert logged[0].get('extra').get('client_info') == {
                u"'key'": u"'value'"}
            # Check that the json written actually contains the client info
            # collapsed up into 'Fields'.
            out.seek(0)
            payload = json.loads(out.readline())
            assert payload['Fields']['key'] == 'value'
            assert payload['Fields']['key2'] == 'value'
            assert payload['Fields']['key3'] is True
            self._port.stopListening()
            pl.stop()
            d.callback(True)
        reactor.callLater(0, check)
        return d

    def test_include_stacktrace_when_no_tb(self):
        pl = PushLogger.setup_logging("Autopush", sentry_dsn=True)

        log.failure("foo", failure.Failure(ZeroDivisionError(), exc_tb=None))
        self.flushLoggedErrors()
        d = Deferred()
        co = sys._getframe().f_code
        filename = co.co_filename
        testname = co.co_name

        def check():
            logged = self.sentry.logged
            if not logged:  # pragma: nocover
                reactor.callLater(0, check)
                return

            assert len(logged) == 1
            # Ensure a top level stacktrace was included
            stacktrace = logged[0]['stacktrace']
            assert any(
                filename == f['abs_path'] and testname == f['function']
                for f in stacktrace['frames'])

            self._port.stopListening()
            pl.stop()
            d.callback(True)
        reactor.callLater(0, check)
        return d


class PushLoggerTestCase(twisted.trial.unittest.TestCase):
    def test_custom_type(self):
        obj = PushLogger.setup_logging("Autopush")
        obj._output = mock_stdout = Mock()
        log.info("omg!", Type=7)
        assert len(mock_stdout.mock_calls) == 2
        kwargs = mock_stdout.mock_calls[0][1][0]
        assert "Type" in kwargs
        obj.stop()

    def test_human_logs(self):
        obj = PushLogger.setup_logging("Autopush", log_format="text")
        obj._output = mock_stdout = Mock()
        log.info("omg!", Type=7)
        assert len(mock_stdout.mock_calls) == 2
        mock_stdout.reset_mock()
        log.error("wtf!", Type=7)
        assert len(mock_stdout.mock_calls) == 2
        obj.stop()

    def test_start_stop(self):
        obj = PushLogger.setup_logging("Autopush")
        obj.start()
        obj.stop()

    def test_file_output(self):
        try:
            os.unlink("testfile.txt")
        except OSError:  # pragma: nocover
            pass
        obj = PushLogger.setup_logging("Autoput", log_output="testfile.txt")
        obj.start()
        log.info("wow")
        obj.stop()
        with open("testfile.txt") as f:
            lines = f.readlines()
        assert len(lines) == 1

    @patch("autopush.logging.boto3")
    def test_firehose_only_output(self, mock_boto3):
        obj = PushLogger("Autoput", log_output="none",
                         firehose_delivery_stream="test")
        obj.firehose = Mock(spec=FirehoseProcessor)
        obj.start()
        log.info("wow")
        obj.stop()
        assert len(obj.firehose.mock_calls) == 3
        assert len(obj.firehose.process.mock_calls) == 1


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
        assert proc._records.full() is True
        proc.process("another")
        assert proc._records.qsize() == 1
        assert proc._records.get() == "test"

    def test_message_max_size(self):
        proc = FirehoseProcessor("test")
        proc.MAX_REQUEST_SIZE = 1

        # Setup the mock
        proc._client.put_record_batch.return_value = dict(FailedPutCount=0)

        # Start and log
        proc.start()
        proc.process("a decently larger message")
        proc.stop()
        assert len(self.mock_boto.mock_calls) == 2
        assert len(proc._client.put_record_batch.mock_calls) == 1

    def test_message_max_batch(self):
        proc = FirehoseProcessor("test")
        proc.MAX_RECORD_BATCH = 1

        # Setup the mock
        proc._client.put_record_batch.return_value = dict(FailedPutCount=0)

        # Start and log
        proc.start()
        proc.process("a decently larger message")
        proc.stop()
        assert len(self.mock_boto.mock_calls) == 2
        assert len(proc._client.put_record_batch.mock_calls) == 1

    def test_queue_timeout(self):
        proc = FirehoseProcessor("test")
        proc.MAX_INTERVAL = 0
        proc._records.get = mock_get = Mock()
        proc._send_record_batch = mock_send = Mock()
        mock_get.side_effect = (Queue.Empty, None)

        proc.start()
        proc.stop()
        mock_send.assert_called()

    def test_batch_send_failure(self):
        proc = FirehoseProcessor("test")
        proc.MAX_RECORD_BATCH = 1

        # Setup the mock
        proc._client.put_record_batch.return_value = dict(FailedPutCount=1)

        # Start and log
        proc.start()
        proc.process("a decently larger message")
        proc.stop()
        assert len(self.mock_boto.mock_calls) == 4
        assert len(proc._client.put_record_batch.mock_calls) == 3
