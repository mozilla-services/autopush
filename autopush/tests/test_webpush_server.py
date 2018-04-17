import random
import time
import unittest
from threading import Event
from uuid import uuid4, UUID

import attr
import factory
from mock import Mock
from twisted.logger import globalLogPublisher
import pytest

from autopush.db import (
    DatabaseManager,
    generate_last_connect,
    make_rotating_tablename,
    Message,
)
from autopush.metrics import SinkMetrics
from autopush.config import AutopushConfig
from autopush.exceptions import ItemNotFound
from autopush.logging import begin_or_register
from autopush.tests.support import TestingLogObserver
from autopush.utils import WebPushNotification, ns_time
from autopush.websocket import USER_RECORD_VERSION
from autopush.webpush_server import (
    CheckStorage,
    DeleteMessage,
    DropUser,
    Hello,
    HelloResponse,
    MigrateUser,
    Register,
    StoreMessages,
    Unregister,
    WebPushMessage,
)
import autopush.tests


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


def generate_version(obj):
    if obj.topic:
        msg_key = ":".join(["01", obj.uaid, obj.channelID.hex,
                            obj.topic])
    else:
        sortkey_timestamp = ns_time()
        msg_key = ":".join(["02", obj.uaid, obj.channelID.hex,
                            str(sortkey_timestamp)])
    # Technically this should be fernet encrypted, but this is fine for
    # testing here
    return msg_key


class WebPushMessageFactory(factory.Factory):
    class Meta:
        model = WebPushMessage

    uaid = factory.LazyFunction(lambda: str(uuid4()))
    channelID = factory.LazyFunction(uuid4)
    ttl = 86400
    data = factory.LazyFunction(
        lambda: random.randint(30, 4096) * "*"
    )
    topic = None
    timestamp = factory.LazyFunction(lambda: int(time.time() * 1000))
    headers = factory.LazyFunction(generate_random_headers)
    version = factory.LazyAttribute(generate_version)


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


def webpush_messages(obj):
    return [attr.asdict(WebPushMessageFactory(uaid=obj.uaid))
            for _ in range(obj.message_count)]


class StoreMessageFactory(factory.Factory):
    class Meta:
        model = StoreMessages

    messages = factory.LazyAttribute(webpush_messages)
    message_month = factory.LazyFunction(
        lambda: make_rotating_tablename("message")
    )

    class Params:
        message_count = 20
        uaid = factory.LazyFunction(lambda: uuid4().hex)


class BaseSetup(unittest.TestCase):
    def setUp(self):
        self.conf = AutopushConfig(
            hostname="localhost",
            resolve_hostname=True,
            port=8080,
            router_port=8081,
            statsd_host=None,
            env="test",
            auto_ping_interval=float(300),
            auto_ping_timeout=float(10),
            close_handshake_timeout=10,
            max_connections=2000000,
        )

        self.logs = TestingLogObserver()
        begin_or_register(self.logs)
        self.addCleanup(globalLogPublisher.removeObserver, self.logs)

        self.db = db = DatabaseManager.from_config(
            self.conf,
            resource=autopush.tests.boto_resource)
        self.metrics = db.metrics = Mock(spec=SinkMetrics)
        db.setup_tables()

    def _store_messages(self, uaid, topic=False, num=5):
        try:
            item = self.db.router.get_uaid(uaid.hex)
            message_table = Message(
                item["current_month"],
                boto_resource=autopush.tests.boto_resource)
        except ItemNotFound:
            message_table = self.db.message
        messages = [WebPushNotificationFactory(uaid=uaid)
                    for _ in range(num)]
        channels = set([m.channel_id for m in messages])
        for channel in channels:
            message_table.register_channel(uaid.hex, channel.hex)
        for idx, notif in enumerate(messages):
            if topic:
                notif.topic = "something_{}".format(idx)
            notif.generate_message_id(self.conf.fernet)
            message_table.store_message(notif)
        return messages


class TestWebPushServer(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import WebPushServer
        return WebPushServer(self.conf, self.db, num_threads=2)

    def test_start_stop(self):
        ws = self._makeFUT()
        ws.start()
        try:
            assert len(ws.workers) == 2
        finally:
            ws.stop()

    def test_hello_process(self):
        ws = self._makeFUT()
        ws.start()
        try:
            hello = HelloFactory()
            result = ws.command_processor.process_message(dict(
                command="hello",
                uaid=hello.uaid.hex,
                connected_at=hello.connected_at,
            ))
            assert "error" not in result
            assert hello.uaid.hex != result["uaid"]
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
        assert isinstance(result, HelloResponse)
        assert hello.uaid != result.uaid
        assert result.check_storage is False
        assert result.connected_at == hello.connected_at
        assert self.metrics.increment.called
        assert self.metrics.increment.call_args[0][0] == 'ua.command.hello'

    def test_existing_uaid(self):
        p = self._makeFUT()
        hello = HelloFactory()
        success, _ = self.db.router.register_user(UserItemFactory(
            uaid=hello.uaid.hex))
        assert success is True
        result = p.process(hello)  # type: HelloResponse
        assert isinstance(result, HelloResponse)
        assert hello.uaid.hex == result.uaid
        assert result.check_storage is True
        assert result.connected_at == hello.connected_at
        assert self.metrics.increment.called
        assert self.metrics.increment.call_args[0][0] == 'ua.command.hello'

    def test_existing_newer_uaid(self):
        p = self._makeFUT()
        hello = HelloFactory()
        self.db.router.register_user(
            UserItemFactory(uaid=hello.uaid.hex,
                            connected_at=hello.connected_at+10)
        )
        result = p.process(hello)  # type: HelloResponse
        assert isinstance(result, HelloResponse)
        assert result.uaid is None


class TestCheckStorageProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import CheckStorageCommand
        return CheckStorageCommand(self.conf, self.db)

    def test_no_messages(self):
        p = self._makeFUT()
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        result = p.process(check)
        assert len(result.messages) == 0

    def test_five_messages(self):
        p = self._makeFUT()
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        self._store_messages(check.uaid, num=5)
        result = p.process(check)
        assert len(result.messages) == 5

    def test_many_messages(self):
        """Test many messages to fill the batches with topics and non-topic

        This is a long test, intended to ensure that all the topic messages
        properly come out and set whether to include the topic flag again or
        proceed to get non-topic messages.

        """
        p = self._makeFUT()
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        self._store_messages(check.uaid, topic=True, num=22)
        self._store_messages(check.uaid, num=15)
        result = p.process(check)
        assert len(result.messages) == 10

        # Delete all the messages returned
        for msg in result.messages:
            notif = msg.to_WebPushNotification()
            self.db.message.delete_message(notif)

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        assert len(result.messages) == 10

        # Delete all the messages returned
        for msg in result.messages:
            notif = msg.to_WebPushNotification()
            self.db.message.delete_message(notif)

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        assert len(result.messages) == 2

        # Delete all the messages returned
        for msg in result.messages:
            notif = msg.to_WebPushNotification()
            self.db.message.delete_message(notif)

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        assert len(result.messages) == 10

        check.timestamp = result.timestamp
        check.include_topic = result.include_topic
        result = p.process(check)
        assert len(result.messages) == 5


class TestDeleteMessageProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import DeleteMessageCommand
        return DeleteMessageCommand(self.conf, self.db)

    def test_delete_message(self):
        from autopush.webpush_server import CheckStorageCommand
        check_command = CheckStorageCommand(self.conf, self.db)
        check = CheckStorageFactory(message_month=self.db.current_msg_month)
        delete_command = self._makeFUT()

        # Store some topic messages
        self._store_messages(check.uaid, topic=True, num=7)

        # Fetch them
        results = check_command.process(check)
        assert len(results.messages) == 7

        # Delete 2 of them
        for notif in results.messages[:2]:
            delete_command.process(DeleteMessage(
                message_month=self.db.current_msg_month,
                message=notif,
            ))

        # Fetch messages again
        results = check_command.process(check)
        assert len(results.messages) == 5


class TestDropUserProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import DropUserCommand
        return DropUserCommand(self.conf, self.db)

    def test_drop_user(self):
        drop_command = self._makeFUT()

        # Create a user
        user = UserItemFactory()
        uaid = user["uaid"]
        self.db.router.register_user(user)

        # Check that its there
        item = self.db.router.get_uaid(uaid)
        assert item is not None

        # Drop it
        drop_command.process(DropUser(uaid=uaid))

        # Verify its gone
        with pytest.raises(ItemNotFound):
            self.db.router.get_uaid(uaid)


class TestMigrateUserProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import MigrateUserCommand
        return MigrateUserCommand(self.conf, self.db)

    def test_migrate_user(self):
        migrate_command = self._makeFUT()

        # Create a user
        last_month = make_rotating_tablename("message", delta=-1)
        user = UserItemFactory(current_month=last_month)
        uaid = user["uaid"]
        self.db.router.register_user(user)

        # Store some messages so we have some channels
        self._store_messages(UUID(uaid), num=3)

        # Check that it's there
        item = self.db.router.get_uaid(uaid)
        _, channels = Message(
            last_month,
            boto_resource=self.db.resource).all_channels(uaid)
        assert item["current_month"] != self.db.current_msg_month
        assert item is not None
        assert len(channels) == 3

        # Migrate it
        migrate_command.process(
            MigrateUser(uaid=uaid, message_month=last_month)
        )

        # Check that it's in the new spot
        item = self.db.router.get_uaid(uaid)
        _, channels = self.db.message.all_channels(uaid)
        assert item["current_month"] == self.db.current_msg_month
        assert item is not None
        assert len(channels) == 3


class TestRegisterProcessor(BaseSetup):

    def _makeFUT(self):
        from autopush.webpush_server import RegisterCommand
        return RegisterCommand(self.conf, self.db)

    def test_register(self):
        cmd = self._makeFUT()
        chid = str(uuid4())
        result = cmd.process(Register(
            uaid=uuid4().hex,
            channel_id=chid,
            message_month=self.db.current_msg_month)
        )
        assert result.endpoint
        assert self.metrics.increment.called
        assert self.metrics.increment.call_args[0][0] == 'ua.command.register'
        assert self.logs.logged(
            lambda e: (e['log_format'] == "Register" and
                       e['channel_id'] == chid and
                       e['endpoint'] == result.endpoint)
        )

    def _test_invalid(self, chid, msg="use lower case, dashed format",
                      status=401):
        cmd = self._makeFUT()
        result = cmd.process(Register(
            uaid=uuid4().hex,
            channel_id=chid,
            message_month=self.db.current_msg_month)
        )
        assert result.error
        assert msg in result.error_msg
        assert status == result.status

    def test_register_bad_chid(self):
        self._test_invalid("oof", "Invalid UUID")

    def test_register_bad_chid_upper(self):
        self._test_invalid(str(uuid4()).upper())

    def test_register_bad_chid_nodash(self):
        self._test_invalid(uuid4().hex)

    def test_register_over_provisioning(self):
        import autopush

        def raise_condition(*args, **kwargs):
            from botocore.exceptions import ClientError
            raise ClientError(
                {'Error': {'Code': 'ProvisionedThroughputExceededException'}},
                'mock_update_item'
            )

        mock_table = Mock(spec=autopush.db.Message)
        mock_table.register_channel = Mock(side_effect=raise_condition)
        self.db.message_table = Mock(return_value=mock_table)
        self._test_invalid(str(uuid4()), "overloaded", 503)


class TestUnregisterProcessor(BaseSetup):

    def _makeFUT(self):
        from autopush.webpush_server import UnregisterCommand
        return UnregisterCommand(self.conf, self.db)

    def test_unregister(self):
        cmd = self._makeFUT()
        chid = str(uuid4())
        result = cmd.process(Unregister(
            uaid=uuid4().hex,
            channel_id=chid,
            message_month=self.db.current_msg_month)
        )
        assert result.success
        assert self.metrics.increment.called
        assert self.metrics.increment.call_args[0][0] == \
            'ua.command.unregister'
        assert self.logs.logged(
            lambda e: (e['log_format'] == "Unregister" and
                       e['channel_id'] == chid)
        )

    def test_unregister_bad_chid(self):
        cmd = self._makeFUT()
        result = cmd.process(Unregister(
            uaid=uuid4().hex,
            channel_id="quux",
            message_month=self.db.current_msg_month)
        )
        assert result.error
        assert "Invalid UUID" in result.error_msg


class TestStoreMessagesProcessor(BaseSetup):
    def _makeFUT(self):
        from autopush.webpush_server import StoreMessagesUserCommand
        return StoreMessagesUserCommand(self.conf, self.db)

    def test_store_messages(self):
        cmd = self._makeFUT()
        store_message = StoreMessageFactory()
        response = cmd.process(store_message)
        assert response.success is True
