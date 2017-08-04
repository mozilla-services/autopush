import random
import time
import unittest
from threading import Event
from uuid import uuid4

import factory
from mock import Mock
from nose.tools import ok_, eq_

from autopush.db import (
    DatabaseManager,
    make_rotating_tablename,
    generate_last_connect,
)
from autopush.metrics import SinkMetrics
from autopush.config import AutopushConfig
from autopush.utils import WebPushNotification
from autopush.websocket import USER_RECORD_VERSION
from autopush.webpush_server import (
    CheckStorage,
    Hello,
    HelloResponse,
    IncStoragePosition,
)


class AutopushCall(object):
    """Placeholder object for real Rust binding one"""
    called = Event()
    val = None
    payload = None

    def complete(self, ret):
        self.val = ret
        self.called.set()

    def json(self):
        return self.payload


class UserItemFactory(factory.Factory):
    class Meta:
        model = dict

    uaid = factory.LazyFunction(lambda: uuid4().hex)
    connected_at = factory.LazyFunction(lambda: int(time.time() * 1000)-10000)
    node_id = "http://something:3242/"
    router_type = "webpush"
    last_connect = factory.LazyFunction(generate_last_connect)
    record_version = USER_RECORD_VERSION
    current_month = factory.LazyFunction(
        lambda: make_rotating_tablename("message")
    )


def generate_random_headers():
    return dict(
        encryption="aesgcm128",
        encryption_key="someneatkey",
        crypto_key="anotherneatkey",
    )


class WebPushNotificationFactory(factory.Factory):
    class Meta:
        model = WebPushNotification

    uaid = factory.LazyFunction(uuid4)
    channel_id = factory.LazyFunction(uuid4)
    ttl = 86400
    data = factory.LazyFunction(
        lambda: random.randint(30, 4096) * "*"
    )
    headers = factory.LazyFunction(generate_random_headers)


class HelloFactory(factory.Factory):
    class Meta:
        model = Hello

    uaid = factory.LazyFunction(lambda: uuid4().hex)
    connected_at = factory.LazyFunction(lambda: int(time.time() * 1000))


class CheckStorageFactory(factory.Factory):
    class Meta:
        model = CheckStorage

    uaid = factory.LazyFunction(lambda: uuid4().hex)
    include_topic = True


class BaseSetup(unittest.TestCase):
    def setUp(self):
        self.conf = AutopushConfig(
            hostname="localhost",
            port=8080,
            statsd_host=None,
            env="test",
            auto_ping_interval=float(300),
            auto_ping_timeout=float(10),
            close_handshake_timeout=10,
            max_connections=2000000,
        )
        self.db = db = DatabaseManager.from_config(self.conf)
        self.metrics = db.metrics = Mock(spec=SinkMetrics)
        db.setup_tables()

    def _store_messages(self, uaid, topic=False, num=5):
        messages = [WebPushNotificationFactory(uaid=uaid)
                    for _ in range(num)]
        channels = set([m.channel_id for m in messages])
        for channel in channels:
            self.db.message.register_channel(uaid.hex, channel.hex)
        for idx, notif in enumerate(messages):
            if topic:
                notif.topic = "something_{}".format(idx)
            notif.generate_message_id(self.conf.fernet)
            self.db.message.store_message(notif)
        return messages


class TestWebPushServer(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import WebPushServer
        return WebPushServer(self.conf, self.db)

    def test_start_stop(self):
        ws = self._makeFUT()
        ws.start(num_threads=2)
        try:
            eq_(len(ws.workers), 2)
        finally:
            ws.stop()
        eq_(len(ws.workers), 0)

    def test_hello_process(self):
        ws = self._makeFUT()
        ws.start(num_threads=2)
        try:
            hello = HelloFactory()
            result = ws.command_processor.process_message(dict(
                command="hello",
                uaid=hello.uaid.hex,
                connected_at=hello.connected_at,
            ))
            ok_("error" not in result)
            ok_(hello.uaid.hex != result["uaid"])
        finally:
            ws.stop()


class TestHelloProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import HelloCommand
        return HelloCommand(self.conf, self.db)

    def test_nonexisting_uaid(self):
        p = self._makeFUT()
        hello = HelloFactory()
        result = p.process(hello)  # type: HelloResponse
        ok_(isinstance(result, HelloResponse))
        ok_(hello.uaid != result.uaid)

    def test_existing_uaid(self):
        p = self._makeFUT()
        hello = HelloFactory()
        success, _ = self.db.router.register_user(UserItemFactory(
            uaid=hello.uaid.hex))
        eq_(success, True)
        result = p.process(hello)  # type: HelloResponse
        ok_(isinstance(result, HelloResponse))
        eq_(hello.uaid.hex, result.uaid)

    def test_existing_newer_uaid(self):
        p = self._makeFUT()
        hello = HelloFactory()
        self.db.router.register_user(
            UserItemFactory(uaid=hello.uaid.hex,
                            connected_at=hello.connected_at+10)
        )
        result = p.process(hello)  # type: HelloResponse
        ok_(isinstance(result, HelloResponse))
        eq_(result.uaid, None)


class TestCheckStorageProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import CheckStorageCommand
        return CheckStorageCommand(self.conf, self.db)

    def test_no_messages(self):
        p = self._makeFUT()
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        result = p.process(check)
        eq_(len(result.messages), 0)

    def test_five_messages(self):
        p = self._makeFUT()
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        self._store_messages(check.uaid, num=5)
        result = p.process(check)
        eq_(len(result.messages), 5)

    def test_many_messages(self):
        """Test many messages to fill the batches with topics and non-topic

        This is a long test, intended to ensure that all the topic messages
        propperly come out and set whether to include the topic flag again or
        proceed to get non-topic messages.

        """
        p = self._makeFUT()
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        self._store_messages(check.uaid, topic=True, num=22)
        self._store_messages(check.uaid, num=15)
        result = p.process(check)
        eq_(len(result.messages), 10)

        # Delete all the messages returned
        for msg in result.messages:
            notif = msg.to_WebPushNotification()
            self.db.message.delete_message(notif)

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        eq_(len(result.messages), 10)

        # Delete all the messages returned
        for msg in result.messages:
            notif = msg.to_WebPushNotification()
            self.db.message.delete_message(notif)

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        eq_(len(result.messages), 2)

        # Delete all the messages returned
        for msg in result.messages:
            notif = msg.to_WebPushNotification()
            self.db.message.delete_message(notif)

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        eq_(len(result.messages), 10)

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        eq_(len(result.messages), 5)


class TestIncrementStorageProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import IncrementStorageCommand
        return IncrementStorageCommand(self.conf, self.db)

    def test_inc_storage(self):
        from autopush.webpush_server import CheckStorageCommand
        inc_command = self._makeFUT()
        check_command = CheckStorageCommand(self.conf, self.db)
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        uaid = check.uaid

        # First store/register some messages
        self._store_messages(check.uaid, num=15)

        # Pull 10 out
        check_result = check_command.process(check)
        eq_(len(check_result.messages), 10)

        # We should now have an updated timestamp returned, increment it
        inc = IncStoragePosition(uaid=uaid.hex,
                                 message_month=self.db.current_msg_month,
                                 timestamp=check_result.timestamp)
        inc_command.process(inc)

        # Create a new check command, and verify we resume from 10 in
        check = CheckStorageFactory(
            uaid=uaid.hex,
            message_month=self.db.current_msg_month
        )
        check_result = check_command.process(check)
        eq_(len(check_result.messages), 5)
