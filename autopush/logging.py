# TWISTED_LOG_MESSAGE and EliotObserver licensed under APL 2.0 from
# ClusterHQ/flocker
# https://github.com/ClusterHQ/flocker/blob/master/flocker/common/script.py#L81-L106
import json
import os
import pkg_resources
import socket
import sys

import raven
from eliot import add_destination, fields, Logger, MessageType
from twisted.python.log import textFromEventDict, startLoggingWithObserver
from twisted.python import log as twisted_log

HOSTNAME = socket.getfqdn()
LOGGER = None
TWISTED_LOG_MESSAGE = MessageType("twisted:log",
                                  fields(error=bool, message=unicode),
                                  u"A log message from Twisted.")


class EliotObserver(object):
    """A Twisted log observer that logs to Eliot."""
    def __init__(self, publisher=twisted_log):
        """
        :param publisher: A ``LogPublisher`` to capture logs from, or if no
            argument is given the default Twisted log system.
        """
        if "SENTRY_DSN" in os.environ:
            self.raven_log = raven.Client(
                release=raven.fetch_package_version())
        else:
            self.raven_log = None
        self.logger = Logger()
        self.publisher = publisher

    def raven_log(self, event):
        f = event['failure']
        self.raven_log.captureException(
            (f.type, f.value, f.getTracebackObject()))

    def __call__(self, msg):
        error = bool(msg.get("isError"))

        if self.raven_log and (error or 'failure' in msg):
            self.raven_log(msg)

        # Twisted log messages on Python 2 are bytes. We don't know the
        # encoding, but assume it's ASCII superset. Charmap will translate
        # ASCII correctly, and higher-bit characters just map to
        # corresponding Unicode code points, and will never fail at decoding.
        message = unicode(textFromEventDict(msg), "charmap")
        TWISTED_LOG_MESSAGE(error=error, message=message).write(self.logger)

    def start(self):
        """Start capturing Twisted logs."""
        startLoggingWithObserver(self, setStdout=False)


def stdout(message):
    msg = {}
    ts = message.pop("timestamp")
    del message["task_level"]
    msg["Hostname"] = HOSTNAME
    if message["error"]:
        msg["Severity"] = 3
    else:
        msg["Severity"] = 5
    for key in ["Type", "EnvVersion", "Severity"]:
        if key in message:
            msg[key] = message.pop(key)
    msg["Timestamp"] = ts * 1000 * 1000 * 1000
    msg["Fields"] = message
    msg["EnvVersion"] = "1.0"
    msg["Logger"] = LOGGER
    sys.stdout.write(json.dumps(msg) + "\n")
add_destination(stdout)


def setup_logging(logger_name):
    global LOGGER
    LOGGER = "-".join([logger_name,
                       pkg_resources.get_distribution("autopush").version])
    ellie = EliotObserver()
    ellie.start()
