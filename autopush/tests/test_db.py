import unittest
import uuid
from datetime import datetime, timedelta

from autopush.websocket import ms_time
from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ProvisionedThroughputExceededException,
    ItemNotFound,
)
from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.items import Item
from mock import Mock
import pytest

from autopush.db import (
    get_rotating_message_table,
    get_router_table,
    create_router_table,
    preflight_check,
    table_exists,
    Message,
    Router,
    generate_last_connect,
    make_rotating_tablename)
from autopush.exceptions import AutopushException
from autopush.metrics import SinkMetrics
from autopush.utils import WebPushNotification


dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))


def make_webpush_notification(uaid, chid, ttl=100):
    message_id = str(uuid.uuid4())
    return WebPushNotification(
        uaid=uuid.UUID(uaid),
        channel_id=uuid.UUID(chid),
        update_id=message_id,
        message_id=message_id,
        ttl=ttl,
    )


class DbCheckTestCase(unittest.TestCase):
    def test_preflight_check_fail(self):
        router = Router(get_router_table(), SinkMetrics())
        message = Message(get_rotating_message_table(), SinkMetrics())

        def raise_exc(*args, **kwargs):  # pragma: no cover
            raise Exception("Oops")

        router.clear_node = Mock()
        router.clear_node.side_effect = raise_exc

        with pytest.raises(Exception):
            preflight_check(message, router)

    def test_preflight_check(self):
        router = Router(get_router_table(), SinkMetrics())
        message = Message(get_rotating_message_table(), SinkMetrics())

        pf_uaid = "deadbeef00000000deadbeef01010101"
        preflight_check(message, router, pf_uaid)
        # now check that the database reports no entries.
        _, notifs = message.fetch_messages(uuid.UUID(pf_uaid))
        assert len(notifs) == 0
        with pytest.raises(ItemNotFound):
            router.get_uaid(pf_uaid)

    def test_preflight_check_wait(self):
        router = Router(get_router_table(), SinkMetrics())
        message = Message(get_rotating_message_table(), SinkMetrics())

        message.table.describe = mock_describe = Mock()

        values = [
            dict(Table=dict(TableStatus="PENDING")),
            dict(Table=dict(TableStatus="ACTIVE")),
        ]

        def return_vals(*args, **kwargs):
            return values.pop(0)

        mock_describe.side_effect = return_vals
        pf_uaid = "deadbeef00000000deadbeef01010101"
        preflight_check(message, router, pf_uaid)
        # now check that the database reports no entries.
        _, notifs = message.fetch_messages(uuid.UUID(pf_uaid))
        assert len(notifs) == 0
        with pytest.raises(ItemNotFound):
            router.get_uaid(pf_uaid)

    def test_get_month(self):
        from autopush.db import get_month
        month0 = get_month(0)
        month1 = get_month(1)
        this_month = month0.month
        next_month = 1 if this_month == 12 else this_month + 1
        assert next_month == month1.month

    def test_zero_fill_month(self):
        from autopush.db import make_rotating_tablename
        assert 'test_2016_03' == make_rotating_tablename(
            'test', date=datetime(2016, 3, 15).date())

    def test_hasher(self):
        import autopush.db as db
        db.key_hash = "SuperSikkret"
        v = db.hasher("01234567123401234123456789ABCDEF")
        assert v == ('0530bb351921e7b4be66831e4c126c6'
                     'd8f614d06cdd592cb8470f31177c8331a')
        db.key_hash = ""

    def test_normalize_id(self):
        # Note, yes, we forbid dashes in UAIDs, and we add them here.
        import autopush.db as db
        abnormal = "deadbeef00000000decafbad00000000"
        normal = "deadbeef-0000-0000-deca-fbad00000000"
        assert db.normalize_id(abnormal) == normal
        with pytest.raises(ValueError):
            db.normalize_id("invalid")
        assert db.normalize_id(abnormal.upper()) == normal


class MessageTestCase(unittest.TestCase):
    def setUp(self):
        table = get_rotating_message_table()
        self.real_table = table
        self.real_connection = table.connection
        self.uaid = str(uuid.uuid4())

    def tearDown(self):
        self.real_table.connection = self.real_connection

    def test_register(self):
        chid = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)

        # Verify its in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        assert len(results) == 1

    def test_unregister(self):
        chid = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)

        # Verify its in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        assert len(results) == 1
        assert results[0]["chids"] == {chid}

        message.unregister_channel(self.uaid, chid)

        # Verify its not in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        assert len(results) == 1
        assert results[0]["chids"] is None

        # Test for the very unlikely case that there's no 'chid'
        m.connection.update_item = Mock()
        m.connection.update_item.return_value = {
            'Attributes': {'uaid': {'S': self.uaid}},
            'ConsumedCapacityUnits': 0.5}
        r = message.unregister_channel(self.uaid, dummy_chid)
        assert r is False

    def test_all_channels(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        _, chans = message.all_channels(self.uaid)
        assert chid in chans
        assert chid2 in chans

        message.unregister_channel(self.uaid, chid2)
        _, chans = message.all_channels(self.uaid)
        assert chid2 not in chans
        assert chid in chans

    def test_save_channels(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        exists, chans = message.all_channels(self.uaid)
        new_uaid = uuid.uuid4().hex
        message.save_channels(new_uaid, chans)
        _, new_chans = message.all_channels(new_uaid)
        assert chans == new_chans

    def test_all_channels_no_uaid(self):
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        exists, chans = message.all_channels(dummy_uaid)
        assert chans == set([])

    def test_message_storage(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        message.store_message(make_webpush_notification(self.uaid, chid))
        message.store_message(make_webpush_notification(self.uaid, chid))
        message.store_message(make_webpush_notification(self.uaid, chid))

        _, all_messages = message.fetch_timestamp_messages(
            uuid.UUID(self.uaid), " ")
        assert len(all_messages) == 3

    def test_message_storage_overwrite(self):
        """Test that store_message can overwrite existing messages which
        can occur in some reconnect cases but shouldn't error"""
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        notif1 = make_webpush_notification(self.uaid, chid)
        notif2 = make_webpush_notification(self.uaid, chid)
        notif3 = make_webpush_notification(self.uaid, chid2)
        notif2.message_id = notif1.message_id
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        message.store_message(notif1)
        message.store_message(notif2)
        message.store_message(notif3)

        all_messages = list(message.fetch_messages(uuid.UUID(self.uaid)))
        assert len(all_messages) == 2

    def test_message_delete_fail_condition(self):
        notif = make_webpush_notification(dummy_uaid, dummy_chid)
        notif.message_id = notif.update_id = dummy_uaid
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        message.table = Mock()
        message.table.delete_item.side_effect = raise_condition
        result = message.delete_message(notif)
        assert result is False

    def test_message_rotate_table_with_date(self):
        prefix = "message" + uuid.uuid4().hex
        future = (datetime.today() + timedelta(days=32)).date()
        tbl_name = make_rotating_tablename(prefix, date=future)

        m = get_rotating_message_table(prefix=prefix, date=future)
        assert m.table_name == tbl_name


class RouterTestCase(unittest.TestCase):
    @classmethod
    def setup_class(self):
        table = get_router_table()
        self.real_table = table
        self.real_connection = table.connection

    @classmethod
    def teardown_class(self):
        self.real_table.connection = self.real_connection

    def _create_minimal_record(self):
        data = {
            "uaid": str(uuid.uuid4()),
            "router_type": "webupsh",
            "last_connect": generate_last_connect(),
            "connected_at": ms_time(),
        }
        return data

    def test_drop_old_users(self):
        # First create a bunch of users
        r = get_router_table()
        router = Router(r, SinkMetrics())
        for _ in range(0, 53):
            router.register_user(self._create_minimal_record())

        results = router.drop_old_users(months_ago=0)
        assert list(results) == [25, 25, 3]

    def test_custom_tablename(self):
        db = DynamoDBConnection()
        db_name = "router_%s" % uuid.uuid4()
        assert not table_exists(db, db_name)
        create_router_table(db_name)
        assert table_exists(db, db_name)

    def test_provisioning(self):
        db_name = "router_%s" % uuid.uuid4()

        r = create_router_table(db_name, 3, 17)
        assert r.throughput["read"] == 3
        assert r.throughput["write"] == 17

    def test_no_uaid_found(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        with pytest.raises(ItemNotFound):
            router.get_uaid(uaid)

    def test_uaid_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.get_item.side_effect = raise_error
        with pytest.raises(ProvisionedThroughputExceededException):
            router.get_uaid(uaid="asdf")

    def test_register_user_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.update_item.side_effect = raise_error
        with pytest.raises(ProvisionedThroughputExceededException):
            router.register_user(dict(uaid=dummy_uaid, node_id="me",
                                      connected_at=1234,
                                      router_type="webpush"))

    def test_clear_node_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table.connection.put_item = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.put_item.side_effect = raise_error
        with pytest.raises(ProvisionedThroughputExceededException):
            router.clear_node(Item(r, dict(uaid=dummy_uaid,
                                           connected_at="1234",
                                           node_id="asdf",
                                           router_type="webpush")))

    def test_incomplete_uaid(self):
        # Older records may be incomplete. We can't inject them using normal
        # methods.
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table.get_item = Mock()
        router.drop_user = Mock()
        router.table.get_item.return_value = {"uaid": uuid.uuid4().hex}
        try:
            router.register_user(dict(uaid=uaid))
        except AutopushException:
            pass
        with pytest.raises(ItemNotFound):
            router.get_uaid(uaid)
        assert router.drop_user.called

    def test_save_new(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        # Sadly, moto currently does not return an empty value like boto
        # when not updating data.
        router.table.connection = Mock()
        router.table.connection.update_item.return_value = {}
        result = router.register_user(dict(uaid="", node_id="me",
                                           router_type="webpush",
                                           connected_at=1234))
        assert result[0] is True

    def test_save_fail(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection = Mock()
        router.table.connection.update_item.side_effect = raise_condition
        router_data = dict(uaid=dummy_uaid, node_id="asdf", connected_at=1234,
                           router_type="webpush")
        result = router.register_user(router_data)
        assert result == (False, {})

    def test_node_clear(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        # Register a node user
        router.register_user(dict(uaid=dummy_uaid, node_id="asdf",
                                  connected_at=1234,
                                  router_type="webpush"))
        # Verify
        user = router.get_uaid(dummy_uaid)
        assert user["node_id"] == "asdf"
        assert user["connected_at"] == 1234
        assert user["router_type"] == "webpush"

        # Clear
        router.clear_node(user)

        # Verify
        user = router.get_uaid(dummy_uaid)
        assert user.get("node_id") is None
        assert user["connected_at"] == 1234
        assert user["router_type"] == "webpush"

    def test_node_clear_fail(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection.put_item = Mock()
        router.table.connection.put_item.side_effect = raise_condition
        data = dict(uaid=dummy_uaid, node_id="asdf", connected_at=1234)
        result = router.clear_node(Item(r, data))
        assert result is False

    def test_drop_user(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        # Register a node user
        router.register_user(dict(uaid=uaid, node_id="asdf",
                                  router_type="webpush",
                                  connected_at=1234))
        result = router.drop_user(uaid)
        assert result is True
        # Deleting already deleted record should return false.
        result = router.drop_user(uaid)
        assert result is False
