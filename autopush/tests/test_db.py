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
from boto.exception import BotoServerError
from mock import Mock
from nose.tools import eq_, assert_raises, ok_

from autopush.db import (
    get_rotating_message_table,
    get_router_table,
    get_storage_table,
    create_router_table,
    create_storage_table,
    preflight_check,
    Storage,
    Message,
    Router,
    generate_last_connect,
    make_rotating_tablename)
from autopush.exceptions import AutopushException
from autopush.metrics import SinkMetrics
from autopush.utils import WebPushNotification


dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))


def setUp():
    from .test_integration import setUp
    setUp()


def tearDown():
    from .test_integration import tearDown
    tearDown()


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
        storage = Storage(get_storage_table(), SinkMetrics())

        def raise_exc(*args, **kwargs):  # pragma: no cover
            raise Exception("Oops")

        router.clear_node = Mock()
        router.clear_node.side_effect = raise_exc

        with assert_raises(Exception):
            preflight_check(storage, router)

    def test_preflight_check(self):
        router = Router(get_router_table(), SinkMetrics())
        storage = Storage(get_storage_table(), SinkMetrics())

        pf_uaid = "deadbeef00000000deadbeef01010101"
        preflight_check(storage, router, pf_uaid)
        # now check that the database reports no entries.
        notifs = storage.fetch_notifications(pf_uaid)
        eq_(len(notifs), 0)
        assert_raises(ItemNotFound, router.get_uaid, pf_uaid)

    def test_preflight_check_wait(self):
        router = Router(get_router_table(), SinkMetrics())
        storage = Storage(get_storage_table(), SinkMetrics())

        storage.table.describe = mock_describe = Mock()

        values = [
            dict(Table=dict(TableStatus="PENDING")),
            dict(Table=dict(TableStatus="ACTIVE")),
        ]

        def return_vals(*args, **kwargs):
            return values.pop(0)

        mock_describe.side_effect = return_vals
        pf_uaid = "deadbeef00000000deadbeef01010101"
        preflight_check(storage, router, pf_uaid)
        # now check that the database reports no entries.
        notifs = storage.fetch_notifications(pf_uaid)
        eq_(len(notifs), 0)
        assert_raises(ItemNotFound, router.get_uaid, pf_uaid)

    def test_get_month(self):
        from autopush.db import get_month
        month0 = get_month(0)
        month1 = get_month(1)
        this_month = month0.month
        next_month = 1 if this_month == 12 else this_month + 1
        eq_(next_month, month1.month)

    def test_zero_fill_month(self):
        from autopush.db import make_rotating_tablename
        eq_('test_2016_03',
            make_rotating_tablename('test', date=datetime(2016, 3, 15)))

    def test_hasher(self):
        import autopush.db as db
        db.key_hash = "SuperSikkret"
        v = db.hasher("01234567123401234123456789ABCDEF")
        eq_(v, '0530bb351921e7b4be66831e4c126c6' +
            'd8f614d06cdd592cb8470f31177c8331a')
        db.key_hash = ""

    def test_normalize_id(self):
        # Note, yes, we forbid dashes in UAIDs, and we add them here.
        import autopush.db as db
        abnormal = "deadbeef00000000decafbad00000000"
        normal = "deadbeef-0000-0000-deca-fbad00000000"
        eq_(db.normalize_id(abnormal), normal)
        assert_raises(ValueError, db.normalize_id, "invalid")
        eq_(db.normalize_id(abnormal.upper()), normal)


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        table = get_storage_table()
        self.real_table = table
        self.real_connection = table.connection

    def tearDown(self):
        self.real_table.connection = self.real_connection

    def test_custom_tablename(self):
        db = DynamoDBConnection()
        db_name = "storage_%s" % uuid.uuid4()
        dblist = db.list_tables()["TableNames"]
        ok_(db_name not in dblist)

        create_storage_table(db_name)
        dblist = db.list_tables()["TableNames"]
        ok_(db_name in dblist)

    def test_provisioning(self):
        db_name = "storage_%s" % uuid.uuid4()

        s = create_storage_table(db_name, 8, 11)
        eq_(s.throughput["read"], 8)
        eq_(s.throughput["write"], 11)

    def test_dont_save_older(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        # Unfortunately moto can't run condition expressions, so
        # we gotta fake it
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        storage.table.connection.put_item.side_effect = raise_error
        result = storage.save_notification(dummy_uaid, dummy_chid, 8)
        eq_(result, False)

    def test_fetch_boto_err(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise BotoServerError(None, None)

        storage.table.connection.put_item.side_effect = raise_error
        with assert_raises(BotoServerError):
            storage.save_notification(dummy_uaid, dummy_chid, 12)

    def test_fetch_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.put_item.side_effect = raise_error
        with assert_raises(ProvisionedThroughputExceededException):
            storage.save_notification(dummy_uaid, dummy_chid, 12)

    def test_save_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        storage.table = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.query_2.side_effect = raise_error
        with assert_raises(ProvisionedThroughputExceededException):
            storage.fetch_notifications(dummy_uaid)

    def test_delete_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.delete_item.side_effect = raise_error
        results = storage.delete_notification(dummy_uaid, dummy_chid)
        eq_(results, False)


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
        eq_(len(results), 1)

    def test_unregister(self):
        chid = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)

        # Verify its in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        eq_(len(results), 1)
        eq_(results[0]["chids"], set([chid]))

        message.unregister_channel(self.uaid, chid)

        # Verify its not in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        eq_(len(results), 1)
        eq_(results[0]["chids"], None)

        # Test for the very unlikely case that there's no 'chid'
        m.connection.update_item = Mock()
        m.connection.update_item.return_value = {
            'Attributes': {'uaid': {'S': self.uaid}},
            'ConsumedCapacityUnits': 0.5}
        r = message.unregister_channel(self.uaid, dummy_chid)
        eq_(r, False)

    def test_all_channels(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        _, chans = message.all_channels(self.uaid)
        ok_(chid in chans)
        ok_(chid2 in chans)

        message.unregister_channel(self.uaid, chid2)
        _, chans = message.all_channels(self.uaid)
        ok_(chid2 not in chans)
        ok_(chid in chans)

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
        eq_(chans, new_chans)

    def test_all_channels_no_uaid(self):
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        exists, chans = message.all_channels(dummy_uaid)
        eq_(chans, set([]))

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
        eq_(len(all_messages), 3)

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
        eq_(len(all_messages), 2)

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
        eq_(result, False)

    def test_message_rotate_table_with_date(self):
        prefix = "message" + uuid.uuid4().hex
        future = datetime.today() + timedelta(days=32)
        tbl_name = make_rotating_tablename(prefix, date=future)

        m = get_rotating_message_table(prefix=prefix, date=future)
        eq_(m.table_name, tbl_name)


class RouterTestCase(unittest.TestCase):
    def setUp(self):
        table = get_router_table()
        self.real_table = table
        self.real_connection = table.connection

    def tearDown(self):
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
        eq_(list(results), [25, 25, 3])

    def test_custom_tablename(self):
        db = DynamoDBConnection()
        db_name = "router_%s" % uuid.uuid4()
        dblist = db.list_tables()["TableNames"]
        ok_(db_name not in dblist)

        create_router_table(db_name)
        dblist = db.list_tables()["TableNames"]
        ok_(db_name in dblist)

    def test_provisioning(self):
        db_name = "router_%s" % uuid.uuid4()

        r = create_router_table(db_name, 3, 17)
        eq_(r.throughput["read"], 3)
        eq_(r.throughput["write"], 17)

    def test_no_uaid_found(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        assert_raises(ItemNotFound, router.get_uaid, uaid)

    def test_uaid_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.get_item.side_effect = raise_error
        with assert_raises(ProvisionedThroughputExceededException):
            router.get_uaid(uaid="asdf")

    def test_register_user_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.update_item.side_effect = raise_error
        with assert_raises(ProvisionedThroughputExceededException):
            router.register_user(dict(uaid=dummy_uaid, node_id="me",
                                      connected_at=1234,
                                      router_type="simplepush"))

    def test_clear_node_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table.connection.put_item = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.put_item.side_effect = raise_error
        with assert_raises(ProvisionedThroughputExceededException):
            router.clear_node(Item(r, dict(uaid=dummy_uaid,
                                           connected_at="1234",
                                           node_id="asdf",
                                           router_type="simplepush")))

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
        assert_raises(ItemNotFound, router.get_uaid, uaid)
        ok_(router.drop_user.called)

    def test_save_new(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        # Sadly, moto currently does not return an empty value like boto
        # when not updating data.
        router.table.connection = Mock()
        router.table.connection.update_item.return_value = {}
        result = router.register_user(dict(uaid="", node_id="me",
                                           router_type="simplepush",
                                           connected_at=1234))
        eq_(result[0], True)

    def test_save_fail(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection = Mock()
        router.table.connection.update_item.side_effect = raise_condition
        router_data = dict(uaid=dummy_uaid, node_id="asdf", connected_at=1234,
                           router_type="simplepush")
        result = router.register_user(router_data)
        eq_(result, (False, {}))

    def test_node_clear(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        # Register a node user
        router.register_user(dict(uaid=dummy_uaid, node_id="asdf",
                                  connected_at=1234,
                                  router_type="webpush"))
        # Verify
        user = router.get_uaid(dummy_uaid)
        eq_(user["node_id"], "asdf")
        eq_(user["connected_at"], 1234)
        eq_(user["router_type"], "webpush")

        # Clear
        router.clear_node(user)

        # Verify
        user = router.get_uaid(dummy_uaid)
        eq_(user.get("node_id"), None)
        eq_(user["connected_at"], 1234)
        eq_(user["router_type"], "webpush")

    def test_node_clear_fail(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection.put_item = Mock()
        router.table.connection.put_item.side_effect = raise_condition
        data = dict(uaid=dummy_uaid, node_id="asdf", connected_at=1234)
        result = router.clear_node(Item(r, data))
        eq_(result, False)

    def test_drop_user(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        # Register a node user
        router.register_user(dict(uaid=uaid, node_id="asdf",
                                  router_type="simplepush",
                                  connected_at=1234))
        result = router.drop_user(uaid)
        eq_(result, True)
        # Deleting already deleted record should return false.
        result = router.drop_user(uaid)
        eq_(result, False)
