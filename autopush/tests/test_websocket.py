import json

import twisted.internet.base
from mock import Mock
from moto import mock_dynamodb2
from txstatsd.metrics.metrics import Metrics
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.trial import unittest

from autopush.settings import AutopushSettings
from autopush.websocket import SimplePushServerProtocol


class WebsocketTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        self.proto = SimplePushServerProtocol()

        settings = AutopushSettings(
            crypto_key="i_CYcNKa2YXrF_7V1Y-2MFfoEl7b6KX55y_9uvOKfJQ=",
            hostname="localhost",
            statsd_host=None,
        )
        self.proto.settings = settings
        self.proto.sendMessage = self.send_mock = Mock()
        self.proto.transport = self.transport_mock = Mock()
        settings.metrics = Mock(spec=Metrics)

    def _connect(self):
        self.proto.onConnect(None)

    def _send_message(self, msg):
        self.proto.onMessage(json.dumps(msg).encode('utf8'), False)

    def _wait_for_message(self, d):
        if self.send_mock.call_args:
            d.callback(self.send_mock.call_args)
            return

        reactor.callLater(0.2, self._wait_for_message, d)

    def _check_response(self, func):
        """Waits for a message to be sent, and runs the func with it"""
        def handle_message(result):
            args, _ = result
            func(json.loads(args[0]))
        d = Deferred()
        d.addCallback(handle_message)
        self._wait_for_message(d)
        return d

    @mock_dynamodb2
    def test_hello(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            assert "messageType" in msg
        return self._check_response(check_result)
