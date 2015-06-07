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

HOSTNAME = socket.getfqdn()
LOGGER = None
TWISTED_LOG_MESSAGE = MessageType("twisted:log",
                                  fields(error=bool, message=unicode),
                                  u"A log message from Twisted.")


class EliotObserver(object):
    """A Twisted log observer that logs to Eliot."""
    def __init__(self):
        if os.environ.get("SENTRY_DSN"):
            self.raven_client = raven.Client(
                release=raven.fetch_package_version("autopush"))
        else:
            self.raven_client = None
        self.logger = Logger()

    def raven_log(self, event):
        f = event['failure']
        self.raven_client.captureException(
            (f.type, f.value, f.getTracebackObject()))

    def __call__(self, msg):
        error = bool(msg.get("isError"))

        if self.raven_client and 'failure' in msg:
            self.raven_log(msg)
            error = True

        # Twisted log messages on Python 2 are bytes. We don't know the
        # encoding, but assume it's ASCII superset. Charmap will translate
        # ASCII correctly, and higher-bit characters just map to
        # corresponding Unicode code points, and will never fail at decoding.
        message = unicode(textFromEventDict(msg), "charmap")
        kw = msg.copy()
        for key in ["message", "isError", "failure", "why", "format"]:
            kw.pop(key, None)
        TWISTED_LOG_MESSAGE(error=error, message=message, **kw).write(
            self.logger)

    def start(self):
        """Start capturing Twisted logs."""
        startLoggingWithObserver(self, setStdout=False)


def stdout(message):
    # uncomment to get concise human readable logging messages.
    if message['error']:
        sys.stdout.write("ERROR: %s\n" % message['message'])
    else:
        sys.stdout.write("       %s\n" % message['message'])
    return
    msg = {}
    ts = message.pop("timestamp")
    del message["task_level"]
    msg["Hostname"] = HOSTNAME
    if message["error"]:
        msg["Severity"] = 3
    else:
        msg["Severity"] = 5

    if "message_type" in message:
        msg["Type"] = message.pop("message_type")

    for key in ["Type", "Severity", "type", "severity"]:
        if key in message:
            msg[key.title()] = message.pop(key)

    msg["Timestamp"] = ts * 1000 * 1000 * 1000
    msg["Fields"] = message
    msg["EnvVersion"] = "2.0"
    msg["Logger"] = LOGGER
    sys.stdout.write(json.dumps(msg) + "\n")


def setup_logging(logger_name):
    global LOGGER
    LOGGER = "-".join([logger_name,
                       pkg_resources.get_distribution("autopush").version])
    add_destination(stdout)
    ellie = EliotObserver()
    ellie.start()
    return ellie
