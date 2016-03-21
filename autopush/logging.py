"""Custom Logging Setup
"""
import io
import json
import pkg_resources
import socket
import sys

import raven
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
    def __init__(self, logger_name, log_level="debug", log_format="json",
                 log_output="stdout", sentry_dsn=None):
        self.logger_name = "-".join([
            logger_name,
            pkg_resources.get_distribution("autopush").version
        ])
        self._filename = None
        self.log_level = LogLevel.lookupByName(log_level)
        if log_output == "stdout":
            self._output = sys.stdout
        else:
            self._filename = log_output
            self._output = "file"
        if log_format == "json":
            self.format_event = self.json_format
        else:
            self.format_event = formatEventAsClassicLogText
        if sentry_dsn:
            self.raven_client = raven.Client(
                release=raven.fetch_package_version("autopush"))
        else:
            self.raven_client = None

    def __call__(self, event):
        if event["log_level"] < self.log_level:
            return

        if self.raven_client and 'failure' in event:
            f = event["failure"]
            reactor.callFromThread(
                self.raven_client.captureException,
                (f.type, f.value, f.getTracebackObject())
            )

        text = self.format_event(event)
        self._output.write(unicode(text))
        self._output.flush()

    def json_format(self, event):
        error = bool(event.get("isError")) or "failure" in event
        ts = event["log_time"]

        if error:
            severity = 3
        else:
            severity = 5

        msg = {
            "Hostname": HOSTNAME,
            "Timestamp": ts * 1000 * 1000 * 1000,
            "Type": "twisted:log",
            "Severity": event.get("severity") or severity,
            "EnvVersion": "2.0",
            "Fields": {k: v for k, v in event.iteritems()
                       if k not in IGNORED_KEYS and
                       type(v) in (str, unicode, list, int, float)},
            "Logger": self.logger_name,
        }
        # Add the nicely formatted message
        msg["Fields"]["message"] = formatEvent(event)
        return json.dumps(msg, skipkeys=True) + "\n"

    def start(self):
        if self._filename:
            self._output = io.open(self._filename, "a", encoding="utf-8")
        globalLogPublisher.addObserver(self)

    def stop(self):
        globalLogPublisher.removeObserver(self)
        if self._filename:
            self._output.close()
            self._output = None

    @classmethod
    def setup_logging(cls, logger_name, log_level="info", log_format="json",
                      log_output="stdout", sentry_dsn=None):
        pl = cls(logger_name, log_level=log_level, log_format=log_format,
                 log_output=log_output, sentry_dsn=sentry_dsn)
        pl.start()
        return pl
