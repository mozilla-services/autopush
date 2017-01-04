"""Custom Logging Setup
"""
import io
import json
import Queue
import pkg_resources
import socket
import sys
import time
import threading

import boto3
import raven
from raven.transport.twisted import TwistedHTTPTransport
from raven.utils.stacks import iter_stack_frames
from twisted.internet import reactor
from twisted.logger import (
    formatEvent,
    formatEventAsClassicLogText,
    globalLogPublisher,
    LogLevel,
    ILogObserver
)
from zope.interface import implementer

HOSTNAME = socket.getfqdn()

# A complete set of keys we don't include in Fields from a log event
IGNORED_KEYS = frozenset([
    "factory",
    "failure",
    "format",
    "isError",
    "log_failure",
    "log_format",
    "log_flattened",
    "log_level",
    "log_legacy",
    "log_logger",
    "log_source",
    "log_system",
    "log_text",
    "log_time",
    "log_trace",
    "message",
    "message_type",
    "severity",
    "task_level",
    "time",
    "timestamp",
    "type",
    "why",
])


@implementer(ILogObserver)
class PushLogger(object):
    """Twisted LogObserver implementation

    Supports firehose delivery, Raven exception reporting, and json/test
    console debugging output.

    """
    def __init__(self, logger_name, log_level="debug", log_format="json",
                 log_output="stdout", sentry_dsn=None,
                 firehose_delivery_stream=None):
        self.logger_name = "-".join([
            logger_name,
            pkg_resources.get_distribution("autopush").version
        ])
        self._filename = None
        self.log_level = LogLevel.lookupByName(log_level)
        if log_output == "stdout":
            self._output = sys.stdout
        elif log_output == "none":
            self._output = None
        else:
            self._filename = log_output
            self._output = None
        if log_format == "json":
            self.format_event = self.json_format
        else:
            self.format_event = formatEventAsClassicLogText
        if sentry_dsn:
            self.raven_client = raven.Client(
                release=raven.fetch_package_version("autopush"),
                transport=TwistedHTTPTransport,
                enable_breadcrumbs=False,
            )
        else:
            self.raven_client = None
        if firehose_delivery_stream:
            self.firehose = FirehoseProcessor(
                stream_name=firehose_delivery_stream)
        else:
            self.firehose = None

    def __call__(self, event):
        if self.raven_client and 'log_failure' in event:
            self.raven_log(event)

        if event["log_level"] < self.log_level:
            return

        text = self.format_event(event)

        if self.firehose:
            self.firehose.process(text)

        if self._output:
            self._output.write(unicode(text))
            self._output.flush()

    def raven_log(self, event):
        f = event["log_failure"]
        stack = None
        extra = dict()
        tb = f.getTracebackObject()
        if not tb:
            # include the current stack for at least some context
            stack = list(iter_stack_frames())[4:]  # approx.
            extra = dict(no_failure_tb=True)
        extra.update(
            log_format=event.get('log_format'),
            log_namespace=event.get('log_namespace'),
            client_info=event.get('client_info'),
            )
        reactor.callFromThread(
            self.raven_client.captureException,
            exc_info=(f.type, f.value, tb),
            stack=stack,
            extra=extra,
        )
        # just in case
        del tb

    def json_format(self, event):
        error = bool(event.get("isError")) or "log_failure" in event
        ts = event["log_time"]

        if error:
            severity = 3
        else:
            severity = 5

        def to_fields(kv):
            reply = dict()
            for k, v in kv:
                if (k not in IGNORED_KEYS and
                        type(v) in (str, unicode, list, int, float)):
                    reply[k] = v
            return reply

        msg = {
            "Hostname": HOSTNAME,
            "Timestamp": ts * 1000 * 1000 * 1000,
            "Type": "twisted:log",
            "Severity": event.get("severity") or severity,
            "EnvVersion": "2.0",
            "Fields": to_fields(event.iteritems()),
            "Logger": self.logger_name,
        }
        # flatten the client_info into Fields
        ci = event.get('client_info')
        if ci and isinstance(ci, dict):
            msg['Fields'].update(
                to_fields(ci.iteritems()))

        # flatten timings into Fields
        ti = event.get('timings')
        if ti and isinstance(ti, dict):
            msg["Fields"].update(
                to_fields(ti.iteritems())
            )

        # Add the nicely formatted message
        msg["Fields"]["message"] = formatEvent(event)
        return json.dumps(msg, skipkeys=True) + "\n"

    def start(self):
        if self._filename:
            self._output = io.open(self._filename, "a", encoding="utf-8")
        if self.firehose:
            self.firehose.start()
        globalLogPublisher.addObserver(self)

    def stop(self):
        globalLogPublisher.removeObserver(self)
        if self._filename:
            self._output.close()
            self._output = None
        if self.firehose:
            self.firehose.stop()

    @classmethod
    def setup_logging(cls, logger_name, log_level="info", log_format="json",
                      log_output="stdout", sentry_dsn=None,
                      firehose_delivery_stream=None):
        pl = cls(logger_name, log_level=log_level, log_format=log_format,
                 log_output=log_output, sentry_dsn=sentry_dsn,
                 firehose_delivery_stream=firehose_delivery_stream)
        pl.start()
        reactor.addSystemEventTrigger('before', 'shutdown', pl.stop)
        return pl


class FirehoseProcessor(object):
    """Batches log events for sending to AWS FireHose"""
    RECORD_SEPARATOR = u"\x1e"
    MAX_RECORD_SIZE = 1024 * 1024
    MAX_REQUEST_SIZE = 4 * 1024 * 1024
    MAX_RECORD_BATCH = 500
    MAX_INTERVAL = 30

    def __init__(self, stream_name, maxsize=0):
        self._records = Queue.Queue(maxsize=maxsize)
        self._prepped = []
        self._total_size = 0
        self._thread = None
        self._client = boto3.client("firehose")
        self._run = False
        self._stream_name = stream_name

    def start(self):
        self._thread = threading.Thread(target=self._worker)
        self._thread.start()

    def stop(self):
        self._records.put_nowait(None)
        self._thread.join()
        self._thread = None

    def process(self, record):
        try:
            self._records.put_nowait(record)
        except Queue.Full:
            # Drop extra records
            pass

    def _worker(self):
        self._last_send = time.time()
        while True:
            time_since_sent = time.time() - self._last_send
            try:
                record = self._records.get(
                    timeout=max(self.MAX_INTERVAL-time_since_sent, 0))
            except Queue.Empty:
                # Send the records
                self._send_record_batch()
                continue

            if record is None:
                # Stop signal so we exit
                break

            # Is this record going to put us over our request size?
            rec_size = len(record) + 1
            if self._total_size + rec_size >= self.MAX_REQUEST_SIZE:
                self._send_record_batch()

            # Store this record
            self._prepped.append(record)
            self._total_size += rec_size

            if len(self._prepped) >= self.MAX_RECORD_BATCH:
                self._send_record_batch()

        # We're done running, send any remaining
        self._send_record_batch()

    def _send_record_batch(self):
        if not self._prepped:
            return

        # Attempt to send the record batch twice, or give up
        tries = 0
        while tries < 3:
            response = self._client.put_record_batch(
                DeliveryStreamName=self._stream_name,
                Records=[{"Data": bytes(self.RECORD_SEPARATOR + record)}
                         for record in self._prepped]
            )
            if response["FailedPutCount"] > 0:
                tries += 1
            else:
                break

        self._prepped = []
        self._total_size = 0
        self._last_send = time.time()
