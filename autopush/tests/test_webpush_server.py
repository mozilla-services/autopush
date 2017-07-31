import time
import unittest
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
from autopush.settings import AutopushSettings
from autopush.websocket import USER_RECORD_VERSION
from autopush.webpush_server import (
    Hello,
    HelloResponse,
)


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


class HelloFactory(factory.Factory):
    class Meta:
        model = Hello

    message_id = factory.LazyFunction(lambda: uuid4().hex)
    uaid = factory.LazyFunction(lambda: uuid4().hex)
    connected_at = factory.LazyFunction(lambda: int(time.time() * 1000))


class TestHelloProcessor(unittest.TestCase):
    def setUp(self):
        self.settings = settings = AutopushSettings(
            hostname="localhost",
            port=8080,
            statsd_host=None,
            env="test",
        )
        self.db = db = DatabaseManager.from_settings(settings)
        self.metrics = db.metrics = Mock(spec=SinkMetrics)
        db.setup_tables()

    def _makeFUT(self):
        from autopush.webpush_server import HelloCommand
        return HelloCommand(self.settings, self.db)

    def test_nonexisting_uaid(self):
        p = self._makeFUT()
        hello = HelloFactory()
        result = p.process(hello)  # type: HelloResponse
        ok_(isinstance(result, HelloResponse))
        ok_(hello.uaid != result.uaid)
        eq_(hello.message_id, result.message_id)

    def test_existing_uaid(self):
        p = self._makeFUT()
        hello = HelloFactory()
        success, _ = self.db.router.register_user(UserItemFactory(
            uaid=hello.uaid.hex))
        eq_(success, True)
        result = p.process(hello)  # type: HelloResponse
        ok_(isinstance(result, HelloResponse))
        eq_(hello.uaid, result.uaid)

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
