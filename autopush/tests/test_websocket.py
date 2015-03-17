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
    @mock_dynamodb2
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
        self.proto.sendClose = self.close_mock = Mock()
        self.proto.transport = self.transport_mock = Mock()
        settings.metrics = Mock(spec=Metrics)

    def _connect(self):
        self.proto.onConnect(None)

    def _send_message(self, msg):
        self.proto.onMessage(json.dumps(msg).encode('utf8'), False)

    def _wait_for_message(self, d):
        args = self.send_mock.call_args
        if args:
            self.send_mock.reset_mock()
            d.callback(args)
            return

        reactor.callLater(0.1, self._wait_for_message, d)

    def _wait_for_close(self, d):
        if self.close_mock.call_args is not None:
            d.callback(True)
            return

        reactor.callLater(0.1, self._wait_for_close, d)

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

    @mock_dynamodb2
    def test_hello_dupe(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_second_hello(msg):
            self.assert_("messageType" in msg)
            self.assertEqual(msg["status"], 401)

        def check_first_hello(msg):
            assert "messageType" in msg
            # Send another hello
            self._send_message(dict(messageType="hello", channelIDs=[]))
            return self._check_response(check_second_hello)
        return self._check_response(check_first_hello)

    @mock_dynamodb2
    def test_not_hello(self):
        self._connect()
        self._send_message(dict(messageType="wooooo"))

        def check_result(result):
            assert result is True
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d
