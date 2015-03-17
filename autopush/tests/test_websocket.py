import json
import uuid

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
        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()
        twisted.internet.base.DelayedCall.debug = True
        self.proto = SimplePushServerProtocol()

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.proto.settings = settings
        self.proto.sendMessage = self.send_mock = Mock()
        self.proto.sendClose = self.close_mock = Mock()
        self.proto.transport = self.transport_mock = Mock()
        settings.metrics = Mock(spec=Metrics)

    def tearDown(self):
        self.mock_dynamodb2.stop()

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

    def test_reporter(self):
        from autopush.websocket import periodic_reporter
        periodic_reporter(self.proto.settings)

        # Verify metric increase of nothing
        calls = self.proto.settings.metrics.method_calls
        self.assertEqual(len(calls), 1)
        name, args, _ = calls[0]
        self.assertEqual(name, "gauge")
        self.assertEqual(args, ("update.client.connections", 0))

    def test_hello(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            self.assert_("messageType" in msg)
        return self._check_response(check_result)

    def test_hello_dupe(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_second_hello(msg):
            self.assertEqual(msg["status"], 401)
            d.callback(True)

        def check_first_hello(msg):
            self.assertEqual(msg["status"], 200)
            # Send another hello
            self._send_message(dict(messageType="hello", channelIDs=[]))
            self._check_response(check_second_hello)
        f = self._check_response(check_first_hello)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_not_hello(self):
        self._connect()
        self._send_message(dict(messageType="wooooo"))

        def check_result(result):
            self.assertEqual(result, True)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_register(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            self.assertEqual(msg["status"], 200)
            self.assertEqual(msg["messageType"], "register")
            self.assert_("pushEndpoint" in msg)
            d.callback(True)

        def check_hello_result(msg):
            self.assert_("messageType" in msg)
            self._send_message(dict(messageType="register",
                                    channelID=str(uuid.uuid4())))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_unregister(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)
        chid = str(uuid.uuid4())

        def check_unregister_result(msg):
            self.assertEqual(msg["status"], 200)
            self.assertEqual(msg["channelID"], chid)
            d.callback(True)

        def check_hello_result(msg):
            self.assertEqual(msg["messageType"], "hello")
            self.assertEqual(msg["status"], 200)
            self._send_message(dict(messageType="unregister",
                                    channelID=chid))
            self._check_response(check_unregister_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_notification(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)
        chid = str(uuid.uuid4())

        def check_hello_result(msg):
            self.assertEqual(msg["status"], 200)
            # Send outself a notification
            payload = [{"channelID": chid, "version": 10}]
            self.proto.send_notifications(payload)

            # Check the call result
            args = self.send_mock.call_args
            self.assert_(args is not None)
            self.send_mock.reset_mock()

            msg = json.loads(args[0][0])
            self.assertEqual(msg["messageType"], "notification")
            self.assert_("updates" in msg)
            self.assert_(len(msg["updates"]), 1)
            update = msg["updates"][0]
            self.assertEqual(update["channelID"], chid)
            self.assertEqual(update["version"], 10)

            # Verify outgoing queue in sent directly
            self.assertEqual(len(self.proto.direct_updates), 1)
            d.callback(True)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ack(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)
        chid = str(uuid.uuid4())

        # stick a notification to ack in
        self.proto.direct_updates[chid] = 12
        self.proto.updates_sent[chid] = 12

        def check_hello_result(msg):
            self.assertEqual(msg["status"], 200)

            # Send our ack
            self._send_message(dict(messageType="ack",
                                    updates=[{"channelID": chid,
                                              "version": 12}]))

            # Verify it was cleared out
            self.assertEqual(len(self.proto.updates_sent), 0)
            self.assertEqual(len(self.proto.direct_updates), 0)
            d.callback(True)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d
