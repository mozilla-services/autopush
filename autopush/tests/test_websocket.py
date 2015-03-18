import json
import uuid

import twisted.internet.base
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_
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
        eq_(len(calls), 1)
        name, args, _ = calls[0]
        eq_(name, "gauge")
        eq_(args, ("update.client.connections", 0))

    def test_handeshake_sub(self):
        self.proto.settings.port = 8080
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            eq_(self.proto.factory.externalPort, None)
            return False

        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})
        self.proto.processHandshake()
        eq_(self.proto.factory.externalPort, 80)

    def test_handshake_nosub(self):
        self.proto.settings.port = 80
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            eq_(self.proto.factory.externalPort, 80)
            return False

        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})
        self.proto.processHandshake()
        eq_(self.proto.factory.externalPort, 80)

    def test_binary_msg(self):
        self.proto.onMessage(b"asdfasdf", True)
        d = Deferred()
        d.addCallback(lambda x: True)
        self._wait_for_close(d)
        return d

    def test_bad_json(self):
        self.proto.onMessage("}{{bad_json!!", False)
        d = Deferred()
        d.addCallback(lambda x: True)
        self._wait_for_close(d)
        return d

    def test_no_messagetype_after_hello(self):
        self._connect()
        self.proto.uaid = "asdf"
        self._send_message(dict(data="wassup"))

        def check_result(result):
            eq_(result, True)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_unknown_messagetype(self):
        self._connect()
        self.proto.uaid = "asdf"
        self._send_message(dict(messageType="wassup"))

        def check_result(result):
            eq_(result, True)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_close_with_cleanup(self):
        self._connect()
        self.proto.uaid = "asdf"
        self.proto.settings.clients["asdf"] = self.proto

        # Stick a mock on
        self.proto._notification_fetch = Mock()
        self.proto.onClose(True, None, None)
        eq_(len(self.proto.settings.clients), 0)
        eq_(len(list(self.proto._notification_fetch.mock_calls)), 1)
        name, _, _ = self.proto._notification_fetch.mock_calls[0]
        eq_(name, "cancel")

    def test_hello(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            eq_(msg["status"], 200)
        return self._check_response(check_result)

    def test_hello_with_uaid(self):
        self._connect()
        uaid = str(uuid.uuid4())
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["uaid"], uaid)
        return self._check_response(check_result)

    def test_hello_with_uaid_no_hypen(self):
        self._connect()
        uaid = str(uuid.uuid4()).replace('-', '')
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["uaid"], uaid)
        return self._check_response(check_result)

    def test_hello_with_bad_uaid(self):
        self._connect()
        uaid = "ajsidlfjlsdjflasjjailsdf"
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            assert msg["uaid"] != uaid
        return self._check_response(check_result)

    def test_hello_dupe(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_second_hello(msg):
            eq_(msg["status"], 401)
            d.callback(True)

        def check_first_hello(msg):
            eq_(msg["status"], 200)
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
            eq_(result, True)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_ping(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()

        def check_ping_result(msg):
            eq_(msg, {})
            d.callback(True)

        def check_result(msg):
            eq_(msg["status"], 200)
            self._send_message({})
            g = self._check_response(check_ping_result)
            g.addErrback(lambda x: d.errback(x))

        f = self._check_response(check_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ping_too_many(self):
        d = self.test_ping()

        closed = Deferred()

        def ping_again(result):
            self._send_message({})
            self._wait_for_close(closed)

        d.addCallback(ping_again)
        return closed

    def test_register(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["messageType"], "register")
            assert "pushEndpoint" in msg
            d.callback(True)

        def check_hello_result(msg):
            assert "messageType" in msg
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
            eq_(msg["status"], 200)
            eq_(msg["channelID"], chid)
            d.callback(True)

        def check_hello_result(msg):
            eq_(msg["messageType"], "hello")
            eq_(msg["status"], 200)
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
            eq_(msg["status"], 200)
            # Send outself a notification
            payload = [{"channelID": chid, "version": 10}]
            self.proto.send_notifications(payload)

            # Check the call result
            args = self.send_mock.call_args
            assert args is not None
            self.send_mock.reset_mock()

            msg = json.loads(args[0][0])
            eq_(msg["messageType"], "notification")
            assert "updates" in msg
            eq_(len(msg["updates"]), 1)
            update = msg["updates"][0]
            eq_(update["channelID"], chid)
            eq_(update["version"], 10)

            # Verify outgoing queue in sent directly
            eq_(len(self.proto.direct_updates), 1)
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
            eq_(msg["status"], 200)

            # Send our ack
            self._send_message(dict(messageType="ack",
                                    updates=[{"channelID": chid,
                                              "version": 12}]))

            # Verify it was cleared out
            eq_(len(self.proto.updates_sent), 0)
            eq_(len(self.proto.direct_updates), 0)
            d.callback(True)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d
