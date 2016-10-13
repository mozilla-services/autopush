import json
import datetime
import time
import uuid
from hashlib import sha256

import twisted.internet.base
from autopush.tests.test_db import make_webpush_notification
from boto.dynamodb2.exceptions import ProvisionedThroughputExceededException
from cyclone.web import Application
from mock import Mock, patch
from nose.tools import assert_raises, eq_, ok_
from txstatsd.metrics.metrics import Metrics
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectError
from twisted.trial import unittest

import autopush.db as db
from autopush.db import create_rotating_message_table
from autopush.settings import AutopushSettings
from autopush.tests import MockAssist
from autopush.utils import WebPushNotification
from autopush.websocket import (
    PushState,
    PushServerProtocol,
    RouterHandler,
    NotificationHandler,
    WebSocketServerProtocol,
)
from autopush.utils import base64url_encode, ms_time


dummy_version = (u'gAAAAABX_pXhN22H-hvscOHsMulKvtC0hKJimrZivbgQPFB3sQAtOPmb'
                 u'0HWIbRgrxIURB6o3nOaNjGk6k-Nhhyo33SAgnXo6827ICGGC1wSoPA4k'
                 u'Bzs5q2i9-hGKgT5oYohxwz84WG3iWDUkaJMM8CMq_9tjoyENoQ_mjFpb'
                 u'Yw7k4oCFcDJxOX8=')
dummy_data = (u'\x73\x7e\xda\x1b\x04\xbb\xed\x48\x2a\x6a\x19\x05\x5f\x8a\x4a'
              u'\xda\x98\xd7\x51\x9e\xc7\xd3\x4e\x8f\x20\x14\x26\x13\xe0\x5d'
              u'\x5d\xac\x81\x10\x1f\xa0\x22')
dummy_headers = {
    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ"
                     "tYWlsdG86IGZvb0BleGFtcGxlLmNvbSIsImV4cCI6IjE0NzYzODA0ND"
                     "QifQ.otqruh-8rm0uI3Ali-Tc49bF0hXOJ30irxedxyTOqh1O1uCler"
                     "dV4kWbGM5en6Ig00hT3lXh_bDa6hnrq5bATA",
    "crypto-key": "keyid=p256dh;dh=BIj2iQzjgqtWBZ9WAz0ybuJkdq5wVco_qdU5Ilv2ro"
                  "0I_fcujPManFGfqUci5gV3Zdm2EcHpLDpD2YPxlzlgxrI,p256ecdsa=BJ"
                  "dLQlHn8RxNWN97P4EPN1E8gTXmyt076dMozixe_4KzfVFVHkqdE60_a0MK"
                  "Yt2-fCwoPnQhXiuMQA7JiLdag2g",
    "encryption": "keyid=p256dh;salt=susKL-fdFoKur1aTjpJ51g",
    "content-encoding": "aesgcm",
    "TTL": "60",
}
dummy_chid = uuid.uuid4()
dummy_chid_str = str(dummy_chid)
dummy_uaid = uuid.uuid4()


def dummy_notif(**kwargs):
    _kwargs = dict(
        uaid=dummy_uaid,
        channel_id=dummy_chid,
        data=dummy_data.encode("utf-8"),
        headers=dummy_headers,
        ttl=20
    )
    _kwargs.update(kwargs)
    return WebPushNotification(**_kwargs)


def setUp():
    from .test_integration import setUp
    setUp()
    create_rotating_message_table()


def tearDown():
    from .test_integration import tearDown
    tearDown()


def assert_called_included(mock, **kwargs):  # pragma: nocover
    """Like assert_called_with but asserts a call was made including
    the specified kwargs (but allowing additional args/kwargs)"""
    mock.assert_called()
    _, mock_kwargs = mock.call_args
    for name, val in kwargs.iteritems():
        if name not in mock_kwargs or mock_kwargs[name] != val:
            raise AssertionError("%s not called with keyword arg %s=%s" %
                                 (mock, name, val))


class WebsocketTestCase(unittest.TestCase):

    def setUp(self):
        from twisted.logger import Logger
        twisted.internet.base.DelayedCall.debug = True
        self.proto = PushServerProtocol()
        self.proto._log_exc = False
        self.proto.log = Mock(spec=Logger)

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
            env="test",
        )
        self.proto.ap_settings = settings
        self.proto.sendMessage = self.send_mock = Mock()
        self.orig_close = self.proto.sendClose
        request_mock = Mock()
        request_mock.headers = {}
        self.proto.ps = PushState(settings=settings, request=request_mock)
        self.proto.sendClose = self.close_mock = Mock()
        self.proto.transport = self.transport_mock = Mock()
        self.proto.closeHandshakeTimeout = 0
        self.proto.autoPingInterval = 300
        self.proto._force_retry = self.proto.force_retry
        settings.metrics = Mock(spec=Metrics)

    def tearDown(self):
        self.proto.force_retry = self.proto._force_retry

    def _connect(self):
        # Do not call agent
        self.proto.ap_settings.agent = Mock()
        self.proto.onConnect(None)

    def _send_message(self, msg):
        self.proto.onMessage(json.dumps(msg).encode('utf8'), False)

    def _wait_for_message(self, d, count=0.0):
        args = self.send_mock.call_args_list
        if len(args) < 1:
            if count > 5.0:  # pragma: nocover
                try:
                    raise Exception("Timeout waiting for a message to send")
                except:
                    d.errback()
            reactor.callLater(0.1, self._wait_for_message, d, count+0.1)
            return

        args = self.send_mock.call_args_list.pop(0)
        return d.callback(args)

    def _wait_for_close(self, d):  # pragma: nocover
        if self.close_mock.call_args is not None:
            d.callback(self.close_mock.call_args)
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

    def test_exc_catcher(self):
        req = Mock()
        self.proto._log_exc = True

        def raise_error(*args, **kwargs):
            raise Exception("Oops")

        req.headers.get.side_effect = raise_error

        self.proto.onConnect(req)
        self.proto.log.failure.assert_called()

    @patch("autopush.websocket.reactor")
    def test_autoping_no_uaid(self, mock_reactor):
        # restore our sendClose
        WebSocketServerProtocol.sendClose = self.proto.sendClose
        WebSocketServerProtocol._sendAutoPing = Mock()
        self.proto.sendClose = self.orig_close
        self._connect()
        self.proto._sendAutoPing()
        ok_(mock_reactor.callLater.called)
        ok_(WebSocketServerProtocol.sendClose.called)

    @patch("autopush.websocket.reactor")
    def test_autoping_uaid_not_in_clients(self, mock_reactor):
        # restore our sendClose
        WebSocketServerProtocol.sendClose = self.proto.sendClose
        WebSocketServerProtocol._sendAutoPing = Mock()
        self.proto.sendClose = self.orig_close
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto._sendAutoPing()
        ok_(mock_reactor.callLater.called)
        ok_(WebSocketServerProtocol.sendClose.called)

    @patch("autopush.websocket.reactor")
    def test_nuke_connection(self, mock_reactor):
        self.proto.transport = Mock()
        self._connect()
        self.proto.state = ""
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.nukeConnection()
        ok_(self.proto.ap_settings.metrics.increment.called)

    @patch("autopush.websocket.reactor")
    def test_nuke_connection_shutdown_ran(self, mock_reactor):
        self.proto.transport = Mock()
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto._shutdown_ran = True
        self.proto.nukeConnection()
        eq_(len(mock_reactor.mock_calls), 0)

    def test_producer_interface(self):
        self._connect()
        self.proto.ps.pauseProducing()
        eq_(self.proto.paused, True)
        self.proto.ps.resumeProducing()
        eq_(self.proto.paused, False)
        eq_(self.proto.ps._should_stop, False)
        self.proto.ps.stopProducing()
        eq_(self.proto.paused, True)
        eq_(self.proto.ps._should_stop, True)

    def test_headers_locate(self):
        from autobahn.websocket.protocol import ConnectionRequest
        req = ConnectionRequest("localhost", {"user-agent": "Me"},
                                "localhost", "/", {}, 1, "localhost",
                                [], [])
        self.proto.onConnect(req)
        eq_(self.proto.ps._user_agent, "Me")

    def test_base_tags(self):
        req = Mock()
        req.headers = {
            'user-agent': "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; "
                          "rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET "
                          "CLR 3.5.30729)"}
        req.host = "example.com:8080"
        ps = PushState(settings=self.proto.ap_settings, request=req)
        eq_(sorted(ps._base_tags),
            sorted(['ua_os_family:Windows',
                    'ua_browser_family:Firefox',
                    'host:example.com:8080']))

    def test_reporter(self):
        from autopush.websocket import periodic_reporter
        self.proto.ap_settings.factory = Mock()
        periodic_reporter(self.proto.ap_settings)

        # Verify metric increase of nothing
        calls = self.proto.ap_settings.metrics.method_calls
        eq_(len(calls), 4)
        name, args, _ = calls[0]
        eq_(name, "gauge")
        eq_(args, ("update.client.writers", 0))

    def test_handeshake_sub(self):
        self.proto.ap_settings.port = 8080
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            eq_(self.proto.factory.externalPort, None)
            return False

        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})
        self.proto.processHandshake()
        eq_(self.proto.factory.externalPort, 80)

    def test_handshake_nosub(self):
        self.proto.ap_settings.port = 80
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            eq_(self.proto.factory.externalPort, 80)
            return False

        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})
        self.proto.processHandshake()
        eq_(self.proto.factory.externalPort, 80)

    def test_handshake_decode_error(self):
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            u'\xfe'.encode('ascii')

        self.proto.failHandshake = Mock()
        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})
        self.proto.processHandshake()
        self.proto.failHandshake.assert_called_with(
            "Error reading handshake data"
        )

    def test_log_exc_disable(self):
        self.proto.log_failure = Mock()
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            raise ValueError()

        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})

        with assert_raises(ValueError):
            self.proto.processHandshake()

        self.proto._log_exc = True
        self.proto.processHandshake()
        self.proto.log_failure.assert_called()

    def test_binary_msg(self):
        self.proto.onMessage(b"asdfasdf", True)
        d = Deferred()
        d.addCallback(lambda x: True)
        self._wait_for_close(d)
        return d

    def test_not_dict(self):
        self.proto.onMessage("[]", False)
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
        self.proto.ps.uaid = "asdf"
        self._send_message(dict(data="wassup"))

        def check_result(close_args):
            _, kwargs = close_args
            eq_(len(kwargs), 0)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_unknown_messagetype(self):
        self._connect()
        self.proto.ps.uaid = "asdf"
        self._send_message(dict(messageType="wassup"))

        def check_result(close_args):
            _, kwargs = close_args
            eq_(len(kwargs), 0)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_close_with_cleanup(self):
        self._connect()
        self.proto.ps.uaid = "asdf"
        self.proto.ap_settings.clients["asdf"] = self.proto

        # Stick a mock on
        notif_mock = Mock()
        self.proto.ps._callbacks.append(notif_mock)
        self.proto.onClose(True, None, None)
        eq_(len(self.proto.ap_settings.clients), 0)
        eq_(len(list(notif_mock.mock_calls)), 1)
        name, _, _ = notif_mock.mock_calls[0]
        eq_(name, "cancel")

    def test_close_with_delivery_cleanup(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ap_settings.clients["asdf"] = self.proto
        chid = str(uuid.uuid4())

        # Stick an un-acked direct notification in
        self.proto.ps.direct_updates[chid] = 12

        # Apply some mocks
        self.proto.ap_settings.storage.save_notification = Mock()
        self.proto.ap_settings.router.get_uaid = mock_get = Mock()
        self.proto.ap_settings.agent = mock_agent = Mock()
        mock_get.return_value = dict(node_id="localhost:2000")

        # Close the connection
        self.proto.onClose(True, None, None)

        d = Deferred()

        def wait_for_agent_call():  # pragma: nocover
            if not mock_agent.mock_calls:
                reactor.callLater(0.1, wait_for_agent_call)
                return

            self.flushLoggedErrors()
            d.callback(True)
        reactor.callLater(0.1, wait_for_agent_call)
        return d

    def test_close_with_delivery_cleanup_using_webpush(self):
        self._connect()
        self.proto.ps.uaid = dummy_uaid.hex
        self.proto.ap_settings.clients[dummy_uaid.hex] = self.proto
        self.proto.ps.use_webpush = True

        # Stick an un-acked direct notification in
        self.proto.ps.direct_updates[dummy_chid_str] = [dummy_notif()]

        # Apply some mocks
        self.proto.ap_settings.message.store_message = Mock()
        self.proto.ap_settings.router.get_uaid = mock_get = Mock()
        self.proto.ap_settings.agent = mock_agent = Mock()
        mock_get.return_value = dict(node_id="localhost:2000")

        # Close the connection
        self.proto.onClose(True, None, None)

        d = Deferred()

        def wait_for_agent_call():  # pragma: nocover
            if not mock_agent.mock_calls:
                reactor.callLater(0.1, wait_for_agent_call)
                return

            self.flushLoggedErrors()
            d.callback(True)
        reactor.callLater(0.1, wait_for_agent_call)
        return d

    def test_close_with_delivery_cleanup_and_no_get_result(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ap_settings.clients["asdf"] = self.proto
        chid = str(uuid.uuid4())

        # Stick an un-acked direct notification in
        self.proto.ps.direct_updates[chid] = 12

        # Apply some mocks
        self.proto.ap_settings.storage.save_notification = Mock()
        self.proto.ap_settings.router.get_uaid = mock_get = Mock()
        self.proto.ps.metrics = mock_metrics = Mock()
        mock_get.return_value = False

        # Close the connection
        self.proto.onClose(True, None, None)

        d = Deferred()

        def wait_for_agent_call():  # pragma: nocover
            if not mock_metrics.mock_calls:
                reactor.callLater(0.1, wait_for_agent_call)

            mock_metrics.increment.assert_called_with(
                "error.notify_uaid_failure", tags=None)
            d.callback(True)
        reactor.callLater(0.1, wait_for_agent_call)
        return d

    def test_close_with_delivery_cleanup_and_no_node_id(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ap_settings.clients["asdf"] = self.proto
        chid = str(uuid.uuid4())

        # Stick an un-acked direct notification in
        self.proto.ps.direct_updates[chid] = 12

        # Apply some mocks
        self.proto.ap_settings.storage.save_notification = Mock()
        self.proto.ap_settings.router.get_uaid = mock_get = Mock()
        mock_get.return_value = mock_node_get = Mock()
        mock_node_get.get.return_value = None

        # Close the connection
        self.proto.onClose(True, None, None)

        d = Deferred()

        def wait_for_agent_call():  # pragma: nocover
            if not mock_node_get.mock_calls:
                reactor.callLater(0.1, wait_for_agent_call)

            d.callback(True)
        reactor.callLater(0.1, wait_for_agent_call)
        return d

    def test_hello_old(self):
        orig_uaid = "deadbeef00000000abad1dea00000000"

        # router.register_user returns (registered, previous
        target_day = datetime.date(2016, 2, 29)
        msg_day = datetime.date(2015, 12, 15)
        msg_date = "{}_{}_{}".format(
            self.proto.ap_settings._message_prefix,
            msg_day.year,
            msg_day.month)
        msg_data = {
            "router_type": "webpush",
            "node_id": "http://localhost",
            "last_connect": int(msg_day.strftime("%s")),
            "current_month": msg_date,
        }
        router = self.proto.ap_settings.router
        router.table.put_item(data=dict(
            uaid=orig_uaid,
            connected_at=ms_time(),
            current_month=msg_date,
            router_type="webpush"
        ))

        def fake_msg(data):
            return (True, msg_data, data)

        mock_msg = Mock(wraps=db.Message)
        mock_msg.fetch_messages.return_value = []
        self.proto.ap_settings.router.register_user = fake_msg
        # because we're faking the dates, process_notifications will key
        # error and fail to return. This will cause the expected path for
        # this test to fail. Since we're requesting the client to change
        # UAIDs anyway, we can safely presume that the non-existant pending
        # notifications are irrelevant for this test.
        self.proto.process_notifications = Mock()
        # massage message_tables to include our fake range
        mt = self.proto.ps.settings.message_tables
        for k in mt.keys():
            del(mt[k])
        mt['message_2016_1'] = mock_msg
        mt['message_2016_2'] = mock_msg
        mt['message_2016_3'] = mock_msg
        with patch.object(datetime, 'date',
                          Mock(wraps=datetime.date)) as patched:
            patched.today.return_value = target_day
            self._connect()
            self._send_message(dict(messageType="hello",
                               uaid=orig_uaid,
                               channelIDs=[],
                               use_webpush=True))

        def check_result(msg):
            eq_(self.proto.ps.rotate_message_table, False)
            # it's fine you've not connected in a while, but
            # you should recycle your endpoints since they're probably
            # invalid by now anyway.
            eq_(msg["status"], 200)
            ok_(msg["uaid"] != orig_uaid)

        return self._check_response(check_result)

    def test_hello_tomorrow(self):
        orig_uaid = "deadbeef00000000abad1dea00000000"
        router = self.proto.ap_settings.router
        router.register_user(dict(
            uaid=orig_uaid,
            connected_at=ms_time(),
            current_month="message_2016_3",
            router_type="simplepush",
        ))

        # router.register_user returns (registered, previous
        target_day = datetime.date(2016, 2, 29)
        msg_day = datetime.date(2016, 3, 1)
        msg_date = "{}_{}_{}".format(
            self.proto.ap_settings._message_prefix,
            msg_day.year,
            msg_day.month)
        msg_data = {
            "router_type": "webpush",
            "node_id": "http://localhost",
            "last_connect": int(msg_day.strftime("%s")),
            "current_month": msg_date,
        }

        def fake_msg(data):
            return (True, msg_data, data)

        mock_msg = Mock(wraps=db.Message)
        mock_msg.fetch_messages.return_value = []
        mock_msg.all_channels.return_value = (None, [])
        self.proto.ap_settings.router.register_user = fake_msg
        # massage message_tables to include our fake range
        mt = self.proto.ps.settings.message_tables
        for k in mt.keys():
            del(mt[k])
        mt['message_2016_1'] = mock_msg
        mt['message_2016_2'] = mock_msg
        mt['message_2016_3'] = mock_msg
        with patch.object(datetime, 'date',
                          Mock(wraps=datetime.date)) as patched:
            patched.today.return_value = target_day
            self._connect()
            self._send_message(dict(messageType="hello",
                               uaid=orig_uaid,
                               channelIDs=[],
                               use_webpush=True))

        d = Deferred()

        def check_rotation(time_spent):
            if time_spent > 3:  # pragma: nocover
                d.errback(Exception("Failed to rotate message table"))

            if self.proto.ps.rotate_message_table:  # pragma: nocover
                reactor.callLater(0.2, check_rotation, 0.2 + time_spent)
                return

            eq_(self.proto.ps.rotate_message_table, False)
            d.callback(True)

        def check_result(msg):
            # it's fine you've not connected in a while, but
            # you should recycle your endpoints since they're probably
            # invalid by now anyway.
            eq_(msg["status"], 200)
            eq_(msg["uaid"], orig_uaid)

            # Wait to see that the message table gets rotated
            reactor.callLater(0.2, check_rotation, 0.2)

        self._check_response(check_result)
        return d

    def test_hello_tomorrow_provision_error(self):
        orig_uaid = "deadbeef00000000abad1dea00000000"
        router = self.proto.ap_settings.router
        router.register_user(dict(
            uaid=orig_uaid,
            connected_at=ms_time(),
            current_month="message_2016_3",
            router_type="simplepush",
        ))

        # router.register_user returns (registered, previous
        target_day = datetime.date(2016, 2, 29)
        msg_day = datetime.date(2016, 3, 1)
        msg_date = "{}_{}_{}".format(
            self.proto.ap_settings._message_prefix,
            msg_day.year,
            msg_day.month)
        msg_data = {
            "router_type": "webpush",
            "node_id": "http://localhost",
            "last_connect": int(msg_day.strftime("%s")),
            "current_month": msg_date,
        }

        def fake_msg(data):
            return (True, msg_data, data)

        mock_msg = Mock(wraps=db.Message)
        mock_msg.fetch_messages.return_value = []
        mock_msg.all_channels.return_value = (None, [])
        self.proto.ap_settings.router.register_user = fake_msg
        # massage message_tables to include our fake range
        mt = self.proto.ps.settings.message_tables
        mt.clear()
        mt['message_2016_1'] = mock_msg
        mt['message_2016_2'] = mock_msg
        mt['message_2016_3'] = mock_msg

        patch_range = patch("autopush.websocket.randrange")
        mock_patch = patch_range.start()
        mock_patch.return_value = 1

        def raise_error(*args):
            raise ProvisionedThroughputExceededException(None, None)

        self.proto.ap_settings.router.update_message_month = MockAssist([
            raise_error,
            Mock(),
        ])

        with patch.object(datetime, 'date',
                          Mock(wraps=datetime.date)) as patched:
            patched.today.return_value = target_day
            self._connect()
            self._send_message(dict(messageType="hello",
                                    uaid=orig_uaid,
                                    channelIDs=[],
                                    use_webpush=True))

        d = Deferred()
        d.addBoth(lambda x: patch_range.stop())

        def check_rotation(time_spent):
            if time_spent > 3:  # pragma: nocover
                d.errback(Exception("Failed to rotate message table"))

            if self.proto.ps.rotate_message_table:  # pragma: nocover
                reactor.callLater(0.2, check_rotation, 0.2 + time_spent)
                return

            eq_(self.proto.ps.rotate_message_table, False)
            d.callback(True)

        def check_result(msg):
            # it's fine you've not connected in a while, but
            # you should recycle your endpoints since they're probably
            # invalid by now anyway.
            eq_(msg["status"], 200)
            eq_(msg["uaid"], orig_uaid)

            # Wait to see that the message table gets rotated
            reactor.callLater(0.2, check_rotation, 0.2)

        self._check_response(check_result)
        return d

    def test_hello(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            eq_(msg["status"], 200)
        return self._check_response(check_result)

    def test_hello_webpush_uses_one_db_call(self):
        db.TRACK_DB_CALLS = True
        db.DB_CALLS = []
        self._connect()
        self._send_message(dict(messageType="hello", use_webpush=True,
                                channelIDs=[]))

        def check_result(msg):
            eq_(db.DB_CALLS, ['register_user', 'fetch_messages'])
            eq_(msg["status"], 200)
            db.DB_CALLS = []
            db.TRACK_DB_CALLS = False
        return self._check_response(check_result)

    def test_hello_with_webpush(self):
        self._connect()
        self._send_message(dict(messageType="hello", use_webpush=True,
                                channelIDs=[]))

        def check_result(msg):
            eq_(msg["status"], 200)
            ok_("use_webpush" in msg)
        eq_(self.proto.base_tags, ['use_webpush:True'])
        return self._check_response(check_result)

    def test_hello_with_missing_router_type(self):
        self._connect()
        uaid = uuid.uuid4().hex
        router = self.proto.ap_settings.router
        router.table.put_item(data=dict(
            uaid=uaid,
            connected_at=ms_time()-1000,
        ))

        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            ok_(msg["uaid"] != uaid)
        return self._check_response(check_result)

    def test_hello_with_missing_current_month(self):
        self._connect()
        uaid = uuid.uuid4().hex
        router = self.proto.ap_settings.router
        router.register_user(dict(
            uaid=uaid,
            connected_at=ms_time(),
            router_type="webpush",
        ))
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid, use_webpush=True))

        def check_result(msg):
            eq_(msg["status"], 200)
            ok_(msg["uaid"] != uaid)
        return self._check_response(check_result)

    def test_hello_with_uaid(self):
        self._connect()
        uaid = uuid.uuid4().hex
        router = self.proto.ap_settings.router
        router.register_user(dict(
            uaid=uaid,
            connected_at=ms_time(),
            router_type="simplepush",
        ))
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
            ok_(msg["uaid"] != uaid)
        return self._check_response(check_result)

    def test_hello_with_bad_uaid_dash(self):
        self._connect()
        uaid = str(uuid.uuid4())
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            ok_(msg["uaid"] != uaid)
        return self._check_response(check_result)

    def test_hello_with_bad_uaid_case(self):
        self._connect()
        uaid = uuid.uuid4().hex.upper()
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            ok_(msg["uaid"] != uaid)
        return self._check_response(check_result)

    def test_hello_failure(self):
        self._connect()
        # Fail out the register_user call
        router = self.proto.ap_settings.router
        router.table.connection.update_item = Mock(side_effect=KeyError)

        self._send_message(dict(messageType="hello", channelIDs=[], stop=1))

        def check_result(msg):
            eq_(msg["status"], 503)
            eq_(msg["reason"], "error")
            self.flushLoggedErrors()

        return self._check_response(check_result)

    def test_hello_provisioned_during_check(self):
        self._connect()
        self.proto.randrange = Mock(return_value=0.1)
        # Fail out the register_user call

        def throw_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router = self.proto.ap_settings.router
        router.table.connection.update_item = Mock(side_effect=throw_error)

        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            eq_(msg["status"], 503)
            eq_(msg["reason"], "error - overloaded")
            self.flushLoggedErrors()

        return self._check_response(check_result)

    def test_hello_check_fail(self):
        self._connect()

        # Fail out the register_user call
        self.proto.ap_settings.router.register_user = \
            Mock(return_value=(False, {}, {}))

        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            calls = self.proto.ap_settings.router.register_user.mock_calls
            eq_(len(calls), 1)
            eq_(msg["status"], 500)
            eq_(msg["reason"], "already_connected")
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

    def test_hello_timeout(self):
        connected = time.time()
        self.proto.ap_settings.hello_timeout = 3
        self._connect()

        def check_elapsed(close_args):
            _, kwargs = close_args
            eq_(len(kwargs), 0)
            ok_(time.time() - connected >= 3)

        d = Deferred()
        d.addCallback(check_elapsed)
        self._wait_for_close(d)
        return d

    def test_hello_timeout_with_wake_timeout(self):
        self.proto.ap_settings.hello_timeout = 3
        self.proto.ap_settings.wake_timeout = 3

        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[],
                                wakeup_host={"ip": "127.0.0.1",
                                             "port": 9999},
                                mobilenetwork={"mcc": "hammer",
                                               "mnc": "banana",
                                               "netid": "gorp",
                                               "ignored": "ok"}))

        def check_elapsed(close_args):
            ok_(ms_time() - self.proto.ps.connected_at >= 3000)
            _, kwargs = close_args
            eq_(kwargs, {"code": 4774, "reason": "UDP Idle"})

        d = Deferred()
        d.addCallback(check_elapsed)
        self._wait_for_close(d)
        return d

    def test_hello_udp(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[],
                                wakeup_host={"ip": "127.0.0.1",
                                             "port": 9999},
                                mobilenetwork={"mcc": "hammer",
                                               "mnc": "banana",
                                               "netid": "gorp",
                                               "ignored": "ok"}))

        def check_result(msg):
            eq_(msg["status"], 200)
            route_data = self.proto.ap_settings.router.get_uaid(
                msg["uaid"]).get('wake_data')
            eq_(route_data, {
                'data': {"ip": "127.0.0.1", "port": 9999, "mcc": "hammer",
                         "mnc": "banana", "netid": "gorp"}})
        return self._check_response(check_result)

    def test_bad_hello_udp(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[],
                                wakeup_host={"port": 9999},
                                mobilenetwork={"mcc": "hammer",
                                               "mnc": "banana",
                                               "netid": "gorp",
                                               "ignored": "ok"}))

        def check_result(msg):
            eq_(msg["status"], 200)
            ok_("wake_data" not in
                self.proto.ap_settings.router.get_uaid(msg["uaid"]).keys())
        return self._check_response(check_result)

    def test_not_hello(self):
        self._connect()
        self._send_message(dict(messageType="wooooo"))

        def check_result(close_args):
            _, kwargs = close_args
            eq_(len(kwargs), 0)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_hello_env(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            eq_(msg["env"], "test")
        return self._check_response(check_result)

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

    def test_ping_too_much(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()

        def check_result(msg):
            eq_(msg["status"], 200)
            self.proto.ps.last_ping = time.time() - 30
            self.proto.sendClose = Mock()
            self._send_message({})
            ok_(self.proto.sendClose.called)
            d.callback(True)

        f = self._check_response(check_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_auto_ping(self):
        self.proto.ps.ping_time_out = False
        self.proto.dropConnection = Mock()
        self.proto.onAutoPingTimeout()
        ok_(self.proto.ps.ping_time_out, True)
        ok_(self.proto.dropConnection.called)

    def test_defer_to_later(self):
        self._connect()

        def fail():
            raise twisted.internet.defer.CancelledError

        def fail2(failure):
            ok_(failure)

        def check_result(result):  # pragma: nocover
            pass

        d = self.proto.deferToLater(0, fail)
        d.addCallback(check_result)
        d.addErrback(fail2)
        ok_(d is not None)

    def test_defer_to_later_cancel(self):
        self._connect()

        f = Deferred()

        def dont_run():  # pragma: nocover
            self.fail("This shouldn't run")

        def trap_cancel(fail):
            fail.trap(twisted.internet.defer.CancelledError)

        def dont_run_callback(result):  # pragma: nocover
            self.fail("Callback shouldn't run")

        d = self.proto.deferToLater(0.2, dont_run)
        d.addCallback(dont_run_callback)
        d.addErrback(trap_cancel)
        d.cancel()
        reactor.callLater(0.2, lambda: f.callback(True))
        return f

    def test_force_retry(self):
        self._connect()

        class Fail(object):
            def __init__(self):
                self.tries = 0

            def __call__(self):
                if self.tries == 0:
                    self.tries += 1
                    raise Exception("oops")
                else:
                    return True

        def check_result(result):
            eq_(result, True)
            self.flushLoggedErrors()

        d = self.proto.force_retry(Fail())
        d.addCallback(check_result)
        ok_(d is not None)
        return d

    def test_register(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[], stop=1))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["messageType"], "register")
            ok_("pushEndpoint" in msg)
            assert_called_included(self.proto.log.info, format="Register")
            d.callback(True)

        def check_hello_result(msg):
            ok_("messageType" in msg)
            self._send_message(dict(messageType="register",
                                    channelID=str(uuid.uuid4())))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_webpush(self):
        self._connect()
        self.proto.ps.use_webpush = True
        chid = str(uuid.uuid4())
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ap_settings.message.register_channel = Mock()

        d = Deferred()

        def check_register_result(msg):
            ok_(self.proto.ap_settings.message.register_channel.called)
            assert_called_included(self.proto.log.info, format="Register")
            d.callback(True)

        res = self.proto.process_register(dict(channelID=chid))
        res.addCallback(check_register_result)
        return d

    def test_register_webpush_with_key(self):
        self._connect()
        self.proto.ps.use_webpush = True
        chid = str(uuid.uuid4())
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ap_settings.message.register_channel = Mock()
        test_key = "SomeRandomCryptoKeyString"
        test_sha = sha256(test_key).hexdigest()
        test_endpoint = ('http://localhost/wpush/v2/' +
                         self.proto.ps.uaid.replace('-', '') +
                         chid.replace('-', '') +
                         test_sha)
        self.proto.sendJSON = Mock()

        def echo(string):
            return string.encode('hex')

        self.proto.ap_settings.fernet.encrypt = echo

        d = Deferred()

        def check_register_result(msg, endpoint):
            eq_(endpoint,
                self.proto.sendJSON.call_args[0][0]['pushEndpoint'])
            ok_(self.proto.ap_settings.message.register_channel.called)
            assert_called_included(self.proto.log.info, format="Register")
            d.callback(True)

        res = self.proto.process_register(
            dict(channelID=chid,
                 key=base64url_encode(test_key)))
        res.addCallback(check_register_result, test_endpoint)
        return d

    def test_register_no_chid(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "register")
            d.callback(True)

        def check_hello_result(msg):
            ok_("messageType" in msg)
            self._send_message(dict(messageType="register"))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_bad_chid(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "register")
            d.callback(True)

        def check_hello_result(msg):
            ok_("messageType" in msg)
            self._send_message(dict(messageType="register", channelID="oof"))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_bad_chid_upper(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "register")
            d.callback(True)

        def check_hello_result(msg):
            ok_("messageType" in msg)
            self._send_message(dict(messageType="register",
                                    channelID=str(uuid.uuid4()).upper()))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_bad_chid_nodash(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "register")
            d.callback(True)

        def check_hello_result(msg):
            ok_("messageType" in msg)
            self._send_message(
                dict(messageType="register",
                     channelID=str(uuid.uuid4()).replace('-', '')))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_bad_crypto(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        def throw_error(*args, **kwargs):
            raise Exception("Crypto explosion")

        self.proto.ap_settings.fernet = Mock(
            **{"encrypt.side_effect": throw_error})
        self._send_message(dict(messageType="register",
                                channelID=str(uuid.uuid4())))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 500)
            eq_(msg["messageType"], "register")
            self.proto.log.failure.assert_called()
            d.callback(True)

        f = self._check_response(check_register_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_kill_others(self):
        self._connect()
        mock_agent = Mock()
        self.proto.ap_settings.agent = mock_agent
        node_id = "http://otherhost"
        uaid = "deadbeef000000000000000000000000"
        self.proto.ps.uaid = uaid
        connected = int(time.time())
        res = dict(node_id=node_id, connected_at=connected, uaid=uaid)
        self.proto._check_other_nodes((True, res, None))
        mock_agent.request.assert_called_with(
            "DELETE",
            "%s/notif/%s/%s" % (node_id, uaid, connected))

    def test_register_kill_others_fail(self):
        self._connect()

        d = Deferred()
        self.proto.ap_settings.agent.request.return_value = d
        node_id = "http://otherhost"
        uaid = "deadbeef000000000000000000000000"
        self.proto.ps.uaid = uaid
        connected = int(time.time())
        res = dict(node_id=node_id, connected_at=connected, uaid=uaid)
        self.proto._check_other_nodes((True, res, None))
        d.errback(ConnectError())
        return d

    def test_register_over_provisioning(self):
        self._connect()
        self.proto.ps.use_webpush = True
        chid = str(uuid.uuid4())
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ap_settings.message.register_channel = register = Mock()

        def throw_provisioned(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        register.side_effect = throw_provisioned

        d = Deferred()

        def check_register_result(_):
            ok_(self.proto.ap_settings.message.register_channel.called)
            ok_(self.send_mock.called)
            args, _ = self.send_mock.call_args
            msg = json.loads(args[0])
            eq_(msg["messageType"], "error")
            eq_(msg["reason"], "overloaded")
            d.callback(True)

        res = self.proto.process_register(dict(channelID=chid))
        res.addCallback(check_register_result)
        return d

    def test_check_kill_self(self):
        self._connect()
        mock_agent = Mock()
        self.proto.ap_settings.agent = mock_agent
        node_id = "http://localhost"
        uaid = "deadbeef000000000000000000000000"
        # Test that the 'existing' connection is newer than the current one.
        connected = int(time.time() * 1000)
        ca = connected + 30000
        ff = Mock()
        ff.ps.connected_at = ca
        self.proto.ap_settings.clients = {uaid: ff}
        self.sendClose = Mock()
        self.proto.sendClose = Mock()
        self.proto.ps.uaid = uaid
        res = dict(node_id=node_id, connected_at=connected, uaid=uaid)
        self.proto._check_other_nodes((True, res, None))
        # the current one should be dropped.
        eq_(ff.sendClose.call_count, 0)
        eq_(self.proto.sendClose.call_count, 1)

    def test_check_kill_existing(self):
        self._connect()
        mock_agent = Mock()
        self.proto.ap_settings.agent = mock_agent
        node_id = "http://localhost"
        uaid = "deadbeef000000000000000000000000"
        # Test that the 'existing' connection is older than the current one.
        connected = int(time.time() * 1000)
        ca = connected - 30000
        ff = Mock()
        ff.ps.connected_at = ca
        self.proto.ap_settings.clients = {uaid: ff}
        self.proto.sendClose = Mock()
        self.proto.ps.uaid = uaid
        res = dict(node_id=node_id, connected_at=connected, uaid=uaid)
        self.proto._check_other_nodes((True, res, None))
        # the existing one should be dropped.
        eq_(ff.sendClose.call_count, 1)
        eq_(self.proto.sendClose.call_count, 0)

    def test_unregister_with_webpush(self):
        chid = str(uuid.uuid4())
        self._connect()
        self.proto.ps.use_webpush = True
        self.proto.force_retry = Mock()
        self.proto.process_unregister(dict(channelID=chid))
        ok_(self.proto.force_retry.called)

    def test_ws_unregister(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)
        chid = str(uuid.uuid4())

        def check_unregister_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["channelID"], chid)
            eq_(len(self.proto.log.mock_calls), 2)
            assert_called_included(self.proto.log.info, format="Unregister")
            d.callback(True)

        def check_hello_result(msg):
            eq_(msg["messageType"], "hello")
            eq_(msg["status"], 200)
            self._send_message(dict(messageType="unregister",
                                    code=104,
                                    channelID=chid))
            self._check_response(check_unregister_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ws_unregister_without_chid(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self._send_message(dict(messageType="unregister"))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_unregister_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "unregister")
            d.callback(True)

        f = self._check_response(check_unregister_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ws_unregister_bad_chid(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self._send_message(dict(messageType="unregister",
                                channelID="}{$@!asdf"))

        d = Deferred()

        def check_unregister_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "unregister")
            d.callback(True)

        f = self._check_response(check_unregister_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ws_unregister_fail(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        chid = str(uuid.uuid4())

        d = Deferred()

        # Replace storage delete with call to fail
        table = self.proto.ap_settings.storage.table
        delete = table.delete_item

        def raise_exception(*args, **kwargs):
            # Stick the original back
            table.delete_item = delete
            raise Exception("Connection problem?")

        table.delete_item = MockAssist([raise_exception, True])
        self._send_message(dict(messageType="unregister",
                                channelID=chid))

        def wait_for_times():  # pragma: nocover
            if not self.proto.log.failure.called:
                reactor.callLater(0.1, wait_for_times)
            else:
                self.proto.log.failure.assert_called_once()
                assert_called_included(self.proto.log.info,
                                       format="Unregister")
                d.callback(True)

        reactor.callLater(0.1, wait_for_times)
        return d

    def test_notification(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        chid = str(uuid.uuid4())

        # Send ourself a notification
        payload = {"channelID": chid, "version": 10}
        self.proto.send_notifications(payload)

        # Check the call result
        args = self.send_mock.call_args
        ok_(args is not None)
        self.send_mock.reset_mock()

        msg = json.loads(args[0][0])
        eq_(msg["messageType"], "notification")
        ok_("updates" in msg)
        eq_(len(msg["updates"]), 1)
        update = msg["updates"][0]
        eq_(update["channelID"], chid)
        eq_(update["version"], 10)

        # Verify outgoing queue in sent directly
        eq_(len(self.proto.ps.direct_updates), 1)

    def test_notification_with_webpush(self):
        self._connect()
        self.proto.ps.use_webpush = True
        self.proto.ps.uaid = uuid.uuid4().hex

        chid = str(uuid.uuid4())
        self.proto.ps.direct_updates[chid] = []

        # Send ourself a notification
        payload = {"channelID": chid,
                   "version": 10,
                   "data": dummy_data.encode('utf-8'),
                   "headers": dummy_headers,
                   "ttl": 20,
                   "timestamp": 0}
        self.proto.send_notifications(payload)

        fixed_headers = dict()
        for header in dummy_headers:
            fixed_headers[header.replace("-", "_")] = dummy_headers[header]

        # Check the call result
        args = json.loads(self.send_mock.call_args[0][0])
        eq_(args, {"messageType": "notification",
                   "channelID": chid,
                   "data": dummy_data,
                   "version": "10",
                   "headers": fixed_headers})

    def test_notification_avoid_newer_delivery(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        chid = str(uuid.uuid4())
        self.proto.ps.updates_sent[chid] = 14

        # Send ourself a notification
        payload = {"channelID": chid, "version": 10}
        self.proto.send_notifications(payload)

        # Check the call result
        args = self.send_mock.call_args
        eq_(args, None)

    def test_ack(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        chid = str(uuid.uuid4())

        # stick a notification to ack in
        self.proto.ps.direct_updates[chid] = 12

        def check_hello_result(msg):
            eq_(msg["status"], 200)

            # Send our ack
            self._send_message(dict(messageType="ack",
                                    updates=[{"channelID": chid,
                                              "version": 12}]))

            # Verify it was cleared out
            eq_(len(self.proto.ps.direct_updates), 0)
            eq_(len(self.proto.log.info.mock_calls), 2)
            assert_called_included(self.proto.log.info,
                                   format="Ack",
                                   router_key="simplepush",
                                   message_source="direct")
            d.callback(True)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ack_with_bad_input(self):
        self._connect()
        eq_(self.proto.ack_update(None), None)

    def test_ack_with_webpush_direct(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        chid = str(uuid.uuid4())

        notif = make_webpush_notification(self.proto.ps.uaid, chid)
        notif.message_id = dummy_version
        self.proto.ps.use_webpush = True
        self.proto.ps.direct_updates[chid] = [notif]

        self.proto.ack_update(dict(
            channelID=chid,
            version=dummy_version
        ))
        eq_(self.proto.ps.direct_updates[chid], [])
        eq_(len(self.proto.log.info.mock_calls), 1)
        assert_called_included(self.proto.log.info,
                               format="Ack",
                               router_key="webpush",
                               message_source="direct")

    def test_ack_with_webpush_from_storage(self):
        self._connect()
        chid = str(uuid.uuid4())
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ps.use_webpush = True
        self.proto.ps.direct_updates[chid] = []
        notif = make_webpush_notification(self.proto.ps.uaid, chid)
        notif.message_id = dummy_version
        self.proto.ps.updates_sent[chid] = [notif]

        mock_defer = Mock()
        self.proto.force_retry = Mock(return_value=mock_defer)
        self.proto.ack_update(dict(
            channelID=chid,
            version=dummy_version,
            code=200
        ))
        ok_(self.proto.force_retry.called)
        ok_(mock_defer.addBoth.called)
        eq_(len(self.proto.log.info.mock_calls), 1)
        assert_called_included(self.proto.log.info,
                               format="Ack",
                               router_key="webpush",
                               message_source="stored")

    def test_nack(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.onMessage(json.dumps(dict(
            messageType="nack",
            version=dummy_version,
            code=200
        )), False)
        eq_(len(self.proto.log.info.mock_calls), 1)

    def test_nack_no_version(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.onMessage(json.dumps(dict(
            messageType="nack",
            code=200
        )), False)
        eq_(len(self.proto.log.info.mock_calls), 0)

    def test_ack_remove(self):
        self._connect()
        notif = dummy_notif()
        self.proto.ps.updates_sent[dummy_chid_str] = [notif]
        self.proto._handle_webpush_update_remove(None, dummy_chid_str, notif)
        eq_(self.proto.ps.updates_sent[dummy_chid_str], [])

    def test_ack_remove_not_set(self):
        self._connect()
        notif = dummy_notif()
        self.proto.ps.updates_sent[dummy_chid_str] = None
        self.proto._handle_webpush_update_remove(None, dummy_chid_str, notif)

    def test_ack_remove_missing(self):
        self._connect()
        notif = dummy_notif()
        self.proto.ps.updates_sent[dummy_chid_str] = []
        self.proto._handle_webpush_update_remove(None, dummy_chid_str, notif)

    def test_ack_fails_first_time(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        class FailFirst(object):
            def __init__(self):
                self.tries = 0

            def __call__(self, *args, **kwargs):
                return self.tries != 0

        self.proto.ap_settings.storage = Mock(
            **{"delete_notification.side_effect": FailFirst()})

        chid = str(uuid.uuid4())

        # stick a notification to ack in
        self.proto.ps.updates_sent[chid] = 12

        # Send our ack
        self._send_message(dict(messageType="ack",
                                updates=[{"channelID": chid,
                                          "version": 12}]))

        # Ask for a notification check again
        self.proto.process_notifications = Mock()
        self.proto.ps._check_notifications = True

        d = Deferred()

        def wait_for_delete():  # pragma: nocover
            calls = self.transport_mock.mock_calls
            if len(calls) < 2:
                reactor.callLater(0.1, wait_for_delete)
                return

            eq_(self.proto.ps.updates_sent, {})
            process_calls = self.proto.process_notifications.mock_calls
            eq_(len(process_calls), 1)
            d.callback(True)

        reactor.callLater(0.1, wait_for_delete)
        return d

    def test_ack_missing_updates(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.sendJSON = Mock()

        self._send_message(dict(messageType="ack"))

        calls = self.proto.sendJSON.call_args_list
        eq_(len(calls), 0)

    def test_ack_missing_chid_version(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        self._send_message(dict(messageType="ack",
                                updates=[{"something": 2}]))

        calls = self.send_mock.call_args_list
        eq_(len(calls), 0)

    def test_ack_untracked(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        self._send_message(dict(messageType="ack",
                                updates=[{"channelID": str(uuid.uuid4()),
                                          "version": 10}]))

        calls = self.send_mock.call_args_list
        eq_(len(calls), 0)

    def test_process_notifications(self):
        twisted.internet.base.DelayedCall.debug = True
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        # Swap out fetch_notifications
        self.proto.ap_settings.storage.fetch_notifications = Mock(
            return_value=[]
        )

        self.proto.process_notifications()

        # Grab a reference to it
        notif_d = self.proto.ps._notification_fetch

        # Run it again to trigger the cancel
        self.proto.process_notifications()

        # Tag on our own to follow up
        d = Deferred()

        # Ensure we catch error outs from either call
        notif_d.addErrback(lambda x: d.errback(x))

        def wait(result):
            eq_(self.proto.ps._notification_fetch, None)
            d.callback(True)
        self.proto.ps._notification_fetch.addCallback(wait)
        self.proto.ps._notification_fetch.addErrback(lambda x: d.errback(x))
        return d

    def test_process_notifications_overload(self):
        twisted.internet.base.DelayedCall.debug = True
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        def throw_error(*args):
            raise ProvisionedThroughputExceededException(None, None)

        # Swap out fetch_notifications
        self.proto.ap_settings.storage.fetch_notifications = MockAssist([
            throw_error,
            [],
        ])

        # Start the randrange patch
        patch_randrange = patch("autopush.websocket.randrange")
        mock_randrange = patch_randrange.start()
        mock_randrange.return_value = 0.1

        # No-op the deferToLater
        self.proto.deferToLater = Mock()

        self.proto.process_notifications()

        # Tag on our own to follow up
        d = Deferred()

        def wait(result):
            ok_(self.proto.deferToLater.called)
            ok_(mock_randrange.called)
            patch_randrange.stop()
            d.callback(True)
        self.proto.ps._notification_fetch.addCallback(wait)
        self.proto.ps._notification_fetch.addErrback(lambda x: d.errback(x))
        return d

    def test_process_notification_error(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex

        def throw_error(*args, **kwargs):
            raise Exception("An error happened!")

        self.proto.ap_settings.storage = Mock(
            **{"fetch_notifications.side_effect": throw_error})
        self.proto.ps._check_notifications = True
        self.proto.process_notifications()

        d = Deferred()

        def check_error(result):
            eq_(self.proto.ps._check_notifications, False)
            ok_(self.proto.log.failure.called)
            d.callback(True)

        self.proto.ps._notification_fetch.addBoth(check_error)
        return d

    def test_process_notif_doesnt_run_with_webpush_outstanding(self):
        self._connect()
        self.proto.ps.uaid = dummy_uaid.hex
        self.proto.ps.use_webpush = True
        self.proto.ps.updates_sent[dummy_chid_str] = [dummy_notif()]
        self.proto.deferToLater = Mock()
        self.proto.process_notifications()
        ok_(self.proto.deferToLater.called)
        eq_(self.proto.ps._notification_fetch, None)

    def test_process_notif_doesnt_run_when_paused(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ps.pauseProducing()
        with patch("autopush.websocket.reactor") as mr:
            self.proto.process_notifications()
            ok_(mr.callLater.mock_calls > 0)

    def test_process_notif_doesnt_run_after_stop(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ps._should_stop = True
        self.proto.process_notifications()
        eq_(self.proto.ps._notification_fetch, None)

    def test_process_notif_paused_on_finish(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ps.pauseProducing()
        with patch("autopush.websocket.reactor") as mr:
            self.proto.finish_notifications(None)
            ok_(mr.callLater.mock_calls > 0)

    def test_notif_finished_with_webpush(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ps.use_webpush = True
        self.proto.deferToLater = Mock()
        self.proto.ps._check_notifications = True
        self.proto.finish_notifications(None)
        ok_(self.proto.deferToLater.called)

    def test_notif_finished_with_webpush_with_notifications(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ps.use_webpush = True
        self.proto.ps._check_notifications = True
        self.proto.process_notifications = Mock()

        notif = make_webpush_notification(
            self.proto.ps.uaid,
            uuid.uuid4().hex,
        )
        self.proto.ps.updates_sent[str(notif.channel_id)] = []

        self.proto.finish_webpush_notifications([notif])
        ok_(self.send_mock.called)

    def test_notif_finished_with_webpush_with_old_notifications(self):
        self._connect()
        self.proto.ps.uaid = uuid.uuid4().hex
        self.proto.ps.use_webpush = True
        self.proto.ps._check_notifications = True
        self.proto.process_notifications = Mock()
        notif = make_webpush_notification(
            self.proto.ps.uaid,
            uuid.uuid4().hex,
            ttl=5
        )
        notif.timestamp = 0
        self.proto.ps.updates_sent[str(notif.channel_id)] = []

        self.proto.force_retry = Mock()
        self.proto.finish_webpush_notifications([notif])
        ok_(self.proto.force_retry.called)
        ok_(not self.send_mock.called)

    def test_notification_results(self):
        # Populate the database for ourself
        uaid = uuid.uuid4().hex
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        chid3 = str(uuid.uuid4())

        # Create a router record
        router = self.proto.ap_settings.router
        router.register_user(dict(
            uaid=uaid,
            connected_at=ms_time(),
            router_type="simplepush",
        ))

        storage = self.proto.ap_settings.storage
        storage.save_notification(uaid, chid, 12)
        storage.save_notification(uaid, chid2, 8)
        storage.save_notification(uaid, chid3, 9)

        self._connect()
        # Indicate we saw a newer direct version of chid2, and an older direct
        # version of chid3
        self.proto.ps.direct_updates[chid2] = 9
        self.proto.ps.direct_updates[chid3] = 8

        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        d = Deferred()

        def check_notifs(msg):
            eq_(msg["messageType"], "notification")
            eq_(len(msg["updates"]), 2)
            for update in msg["updates"]:
                uchid = update["channelID"]
                ver = update["version"]
                if uchid == chid:
                    eq_(ver, 12)
                elif uchid == chid3:
                    eq_(ver, 9)
                ok_(uchid in [chid, chid3])
            d.callback(True)

        def check_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["messageType"], "hello")

            # Now wait for the notification results
            nd = self._check_response(check_notifs)
            nd.addErrback(lambda x: d.errback(x))

        cd = self._check_response(check_result)
        cd.addErrback(lambda x: d.errback(x))
        return d

    def test_notification_dont_deliver_after_ack(self):
        self._connect()

        uaid = uuid.uuid4().hex
        chid = str(uuid.uuid4())

        # Create a dummy router record
        router = self.proto.ap_settings.router
        router.register_user(dict(
            uaid=uaid,
            connected_at=ms_time(),
            router_type="simplepush",
        ))

        storage = self.proto.ap_settings.storage
        storage.save_notification(uaid, chid, 10)

        # Verify the message is stored
        results = storage.fetch_notifications(uaid)
        eq_(len(results), 1)

        self._send_message(dict(messageType="hello", channelIDs=[], uaid=uaid))

        d = Deferred()

        def wait_for_clear(count=0.0):
            if self.proto.ps.updates_sent:  # pragma: nocover
                if count > 5.0:
                    d.errback(Exception("Time-out waiting"))
                reactor.callLater(0.1, wait_for_clear, count+0.1)
                return

            # Accepting again
            eq_(self.proto.ps.updates_sent, {})

            # Check that storage is clear
            notifs = storage.fetch_notifications(uaid)
            eq_(len(notifs), 0)
            d.callback(True)

        def check_notif_result(msg):
            eq_(msg["messageType"], "notification")
            updates = msg["updates"]
            eq_(len(updates), 1)
            eq_(updates[0]["channelID"], chid)
            eq_(updates[0]["version"], 10)
            # Send our ack
            self._send_message(dict(messageType="ack",
                                    updates=[{"channelID": chid,
                                              "version": 10}]))
            # Wait for updates to be cleared and notifications accepted again
            reactor.callLater(0.1, wait_for_clear)

        def check_hello_result(msg):
            eq_(msg["status"], 200)

            # Now wait for the notification
            nd = self._check_response(check_notif_result)
            nd.addErrback(lambda x: d.errback(x))
        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_notification_dont_deliver(self):
        # Populate the database for ourself
        uaid = uuid.uuid4().hex
        chid = str(uuid.uuid4())

        # Create a dummy router record
        router = self.proto.ap_settings.router
        router.register_user(dict(
            uaid=uaid,
            connected_at=ms_time(),
            router_type="simplepush",
        ))

        storage = self.proto.ap_settings.storage
        storage.save_notification(uaid, chid, 12)

        # Verify the message is stored
        results = storage.fetch_notifications(uaid)
        eq_(len(results), 1)

        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        d = Deferred()

        def check_mock_call(count=0.0):
            calls = self.proto.process_notifications.mock_calls
            if len(calls) < 1:
                if count > 5.0:  # pragma: nocover
                    raise Exception("Time-out waiting")
                reactor.callLater(0.1, check_mock_call, count+0.1)
                return

            eq_(len(calls), 1)
            d.callback(True)

        def check_call(result):
            send_calls = self.send_mock.mock_calls
            # There should be one, for the hello response
            # No notifications should've been delivered after
            # this notifiation check
            eq_(len(send_calls), 1)

            # Now we wait for the mock call to run
            reactor.callLater(0.1, check_mock_call)

        # Run immediately after hello was processed
        def after_hello(result):
            # Setup updates_sent to avoid a notification send
            self.proto.ps.updates_sent[chid] = 14

            # Notification check has started, indicate to check
            # notifications again
            self.proto.ps._check_notifications = True

            # Now replace process_notifications so it won't be
            # run again
            self.proto.process_notifications = Mock()

            # Chain our check for the call
            self.proto.ps._notification_fetch.addBoth(check_call)
            self.proto.ps._notification_fetch.addErrback(
                lambda x: d.errback(x))
        self.proto.ps._register.addCallback(after_hello)
        self.proto.ps._register.addErrback(lambda x: d.errback(x))
        return d

    def test_incomplete_uaid(self):
        mm = self.proto.ap_settings.router = Mock()
        fr = self.proto.force_retry = Mock()
        uaid = uuid.uuid4().hex
        mm.get_uaid.return_value = {
            'uaid': uaid
        }
        self.proto.ps.uaid = uaid
        reply = self.proto._verify_user_record()
        eq_(reply, None)
        ok_(fr.called)
        eq_(fr.call_args[0], (mm.drop_user, uaid))


class RouterHandlerTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True

        self.ap_settings = settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        settings.metrics = Mock(spec=Metrics)
        self.mock_request = Mock()
        self.handler = RouterHandler(Application(), self.mock_request,
                                     ap_settings=settings)
        self.handler.set_status = self.status_mock = Mock()
        self.handler.write = self.write_mock = Mock()

    def test_client_connected(self):
        uaid = uuid.uuid4().hex
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        client_mock.paused = False
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(len(client_mock.mock_calls), 1)

    def test_client_not_connected(self):
        uaid = uuid.uuid4().hex
        self.mock_request.body = "{}"
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(len(self.status_mock.mock_calls), 1)
        self.status_mock.assert_called_with(404, reason=None)

    def test_client_connected_but_busy(self):
        uaid = uuid.uuid4().hex
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        client_mock.accept_notification = False
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        self.status_mock.assert_called_with(503, reason=None)


class NotificationHandlerTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True

        self.ap_settings = settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        settings.metrics = Mock(spec=Metrics)
        self.mock_request = Mock()
        self.handler = NotificationHandler(Application(), self.mock_request,
                                           ap_settings=settings)
        self.handler.set_status = self.status_mock = Mock()
        self.handler.write = self.write_mock = Mock()

    def test_connected_and_free(self):
        uaid = uuid.uuid4().hex
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        client_mock.paused = False
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(len(client_mock.mock_calls), 1)

    def test_connected_and_busy(self):
        uaid = uuid.uuid4().hex
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        client_mock.paused = True
        client_mock._check_notifications = False
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(client_mock._check_notifications, True)
        eq_(self.status_mock.call_args, ((202,),))

    def test_not_connected(self):
        uaid = uuid.uuid4().hex
        self.mock_request.body = "{}"
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        self.status_mock.assert_called_with(404, reason=None)

    def test_delete(self):
        uaid = uuid.uuid4().hex
        now = int(time.time() * 1000)
        self.ap_settings.clients[uaid] = mock_client = Mock()
        mock_client.ps = Mock()
        mock_client.ps.connected_at = now
        mock_client.sendClose = Mock()
        self.handler.delete(uaid, "", now)
        ok_(mock_client.sendClose.called)
