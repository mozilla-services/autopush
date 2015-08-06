import os
import signal
import subprocess
from unittest.case import SkipTest

import boto
import psutil
from twisted.trial import unittest
from twisted.internet import reactor

here_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.dirname(os.path.dirname(here_dir))
moto_process = None


def setUp():
    boto_path = os.path.join(root_dir, "automock", "boto.cfg")
    boto.config.load_from_path(boto_path)
    if "SKIP_INTEGRATION" in os.environ:  # pragma: nocover
        raise SkipTest("Skipping integration tests")
    global moto_process
    cmd = "moto_server dynamodb2 -p 5000"
    moto_process = subprocess.Popen(cmd, shell=True, env=os.environ)


def tearDown():
    global moto_process
    # This kinda sucks, but its the only way to nuke the child procs
    proc = psutil.Process(pid=moto_process.pid)
    child_procs = proc.children(recursive=True)
    for p in [proc] + child_procs:
        os.kill(p.pid, signal.SIGTERM)
    moto_process.wait()

    # Clear out the boto config that was loaded so the rest of the tests run
    # fine
    for section in boto.config.sections():
        boto.config.remove_section(section)


class TestIntegration(unittest.TestCase):
    def setUp(self):
        from autobahn.twisted.websocket import WebSocketServerFactory
        from autopush.settings import AutopushSettings
        from autopush.websocket import SimplePushServerProtocol
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        factory = WebSocketServerFactory("ws://localhost:9010/")
        factory.protocol = SimplePushServerProtocol
        factory.protocol.ap_settings = settings
        factory.setProtocolOptions(
            webStatus=False,
            maxFramePayloadSize=2048,
            maxMessagePayloadSize=2048,
            openHandshakeTimeout=5,
        )
        settings.factory = factory
        self.websocket = reactor.listenTCP(9010, factory)

    def tearDown(self):
        self.websocket.stopListening()

    def test_basic(self):
        pass
