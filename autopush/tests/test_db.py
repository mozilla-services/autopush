import unittest
import uuid
import time

from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ProvisionedThroughputExceededException,
    ItemNotFound,
)
from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.items import Item
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_

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
)
from autopush.metrics import SinkMetrics


mock_db2 = mock_dynamodb2()


def setUp():
    mock_db2.start()


def tearDown():
    mock_db2.stop()


class DbCheckTestCase(unittest.TestCase):
    def test_preflight_check(self):
        router_table = get_router_table()
        storage_table = get_storage_table()

        def raise_exc(*args, **kwargs):  # pragma: no cover
            raise Exception("Oops")

        router_table.clear_node = Mock()
        router_table.clear_node.side_effect = raise_exc

        with self.assertRaises(Exception):
            preflight_check(storage_table, router_table)

    def test_get_month(self):
        from autopush.db import get_month
        month0 = get_month(0)
        month1 = get_month(1)
        this_month = month0.month
        next_month = 1 if this_month == 12 else this_month + 1
        eq_(next_month, month1.month)

    def test_hasher(self):
        import autopush.db as db
        db.key_hash = "SuperSikkret"
        v = db.hasher("01234567123401234123456789ABCDEF")
        eq_(v, '0530bb351921e7b4be66831e4c126c6' +
            'd8f614d06cdd592cb8470f31177c8331a')
        db.key_hash = ""


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
        assert db_name not in dblist

        create_storage_table(db_name)
        dblist = db.list_tables()["TableNames"]
        assert db_name in dblist

    def test_provisioning(self):
        db_name = "storage_%s" % uuid.uuid4()

        s = create_storage_table(db_name, 8, 11)
        assert s.throughput["read"] == 8
        assert s.throughput["write"] == 11

    def test_dont_save_older(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        # Unfortunately moto can't run condition expressions, so
        # we gotta fake it
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        storage.table.connection.put_item.side_effect = raise_error
        result = storage.save_notification("fdas",  "asdf", 8)
        eq_(result, False)

    def test_fetch_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.put_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            storage.save_notification("asdf", "asdf", 12)

    def test_save_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        storage.table = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.query_2.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            storage.fetch_notifications("asdf")

    def test_delete_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, SinkMetrics())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.delete_item.side_effect = raise_error
        results = storage.delete_notification("asdf", "asdf")
        eq_(results, False)


class MessageTestCase(unittest.TestCase):
    def setUp(self):
        table = get_rotating_message_table()
        self.real_table = table
        self.real_connection = table.connection
        self.uaid = str(uuid.uuid4())

    def tearDown(self):
        self.real_table.connection = self.real_connection

    def _nstime(self):
        return int(time.time() * 1000 * 1000)

    def test_register(self):
        chid = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)

        # Verify its in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        assert(len(results) == 1)

    def test_unregister(self):
        chid = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)

        # Verify its in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        assert(len(results) == 1)
        eq_(results[0]["chids"], set([chid]))

        message.unregister_channel(self.uaid, chid)

        # Verify its not in the db
        rows = m.query_2(uaid__eq=self.uaid, chidmessageid__eq=" ")
        results = list(rows)
        assert(len(results) == 1)
        eq_(results[0]["chids"], set([]))

        # Test for the very unlikely case that there's no 'chid'
        m.connection.update_item = Mock()
        m.connection.update_item.return_value = {
            'Attributes': {'uaid': {'S': self.uaid}},
            'ConsumedCapacityUnits': 0.5}
        r = message.unregister_channel(self.uaid, "test")
        eq_(r, False)

    def test_all_channels(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        _, chans = message.all_channels(self.uaid)
        assert(chid in chans)
        assert(chid2 in chans)

        message.unregister_channel(self.uaid, chid2)
        _, chans = message.all_channels(self.uaid)
        assert(chid2 not in chans)
        assert(chid in chans)

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
        exists, chans = message.all_channels("asdf")
        assert(chans == set([]))

    def test_message_storage(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        data1 = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        ttl = int(time.time())+100
        time1, time2, time3 = self._nstime(), self._nstime(), self._nstime()+1
        message.store_message(self.uaid, chid, time1, ttl, data1, {})
        message.store_message(self.uaid, chid2, time2, ttl, data2, {})
        message.store_message(self.uaid, chid2, time3, ttl, data1, {})

        all_messages = list(message.fetch_messages(self.uaid))
        eq_(len(all_messages), 3)

        message.delete_messages_for_channel(self.uaid, chid2)
        all_messages = list(message.fetch_messages(self.uaid))
        eq_(len(all_messages), 1)

        message.delete_message(self.uaid, chid, time1)
        all_messages = list(message.fetch_messages(self.uaid))
        eq_(len(all_messages), 0)

    def test_delete_user(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        data1 = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        ttl = int(time.time())+100
        time1, time2, time3 = self._nstime(), self._nstime(), self._nstime()+1
        message.store_message(self.uaid, chid, time1, ttl, data1, {})
        message.store_message(self.uaid, chid2, time2, ttl, data2, {})
        message.store_message(self.uaid, chid2, time3, ttl, data1, {})

        message.delete_user(self.uaid)
        all_messages = list(message.fetch_messages(self.uaid))
        eq_(len(all_messages), 0)

    def test_message_delete_pagination(self):
        def make_messages(channel_id, count):
            m = []
            t = self._nstime()
            ttl = int(time.time())+200
            for i in range(count):
                m.append(
                    (self.uaid, channel_id, str(uuid.uuid4()), ttl, {}, t+i)
                )
            return m

        chid = str(uuid.uuid4())
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        message.register_channel(self.uaid, chid)

        # Shove 80 messages in
        for message_args in make_messages(chid, 80):
            message.store_message(*message_args)

        # Verify we can see them all
        all_messages = list(message.fetch_messages(self.uaid, limit=100))
        eq_(len(all_messages), 80)

        # Delete them all
        message.delete_messages_for_channel(self.uaid, chid)

        # Verify they're gone
        all_messages = list(message.fetch_messages(self.uaid, limit=100))
        eq_(len(all_messages), 0)

    def test_message_delete_fail_condition(self):
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        message.table = Mock()
        message.table.delete_item.side_effect = raise_condition
        result = message.delete_message(uaid="asdf", channel_id="asdf",
                                        message_id="asdf", updateid="asdf")
        eq_(result, False)

    def test_update_message(self):
        chid = uuid.uuid4().hex
        m = get_rotating_message_table()
        message = Message(m, SinkMetrics())
        data1 = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        time1 = self._nstime()
        time2 = self._nstime()+100
        ttl = self._nstime()+1000
        message.store_message(self.uaid, chid, time1, ttl, data1, {})
        message.update_message(self.uaid, chid, time2, ttl, data2, {})
        messages = list(message.fetch_messages(self.uaid))
        eq_(data2, messages[0]['#dd'])

    def test_update_message_fail(self):
        message = Message(get_rotating_message_table(), SinkMetrics)
        message.store_message(self.uaid,
                              uuid.uuid4().hex,
                              self._nstime(),
                              str(uuid.uuid4()),
                              {})
        u = message.table.connection.update_item = Mock()

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        u.side_effect = raise_condition
        b = message.update_message(self.uaid,
                                   uuid.uuid4().hex,
                                   self._nstime(),
                                   str(uuid.uuid4()),
                                   {})
        eq_(b, False)


class RouterTestCase(unittest.TestCase):
    def setUp(self):
        table = get_router_table()
        self.real_table = table
        self.real_connection = table.connection

    def tearDown(self):
        self.real_table.connection = self.real_connection

    def test_custom_tablename(self):
        db = DynamoDBConnection()
        db_name = "router_%s" % uuid.uuid4()
        dblist = db.list_tables()["TableNames"]
        assert db_name not in dblist

        create_router_table(db_name)
        dblist = db.list_tables()["TableNames"]
        assert db_name in dblist

    def test_provisioning(self):
        db_name = "router_%s" % uuid.uuid4()

        r = create_router_table(db_name, 3, 17)
        assert r.throughput["read"] == 3
        assert r.throughput["write"] == 17

    def test_no_uaid_found(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        self.assertRaises(ItemNotFound, router.get_uaid, uaid)

    def test_uaid_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.get_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            router.get_uaid(uaid="asdf")

    def test_register_user_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.update_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            router.register_user(dict(uaid="asdf", node_id="me",
                                 connected_at=1234))

    def test_clear_node_provision_failed(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        router.table.connection.put_item = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.put_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            router.clear_node(Item(r, dict(uaid="asdf", connected_at="1234",
                                           node_id="asdf")))

    def test_save_uaid(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        result = router.register_user(dict(uaid=uaid, node_id="me",
                                      connected_at=1234))
        eq_(result[0], True)
        eq_(result[1], {"uaid": uaid,
                        "connected_at": 1234,
                        "node_id": "me"})
        result = router.get_uaid(uaid)
        eq_(bool(result), True)
        eq_(result["node_id"], "me")

    def test_save_new(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())
        # Sadly, moto currently does not return an empty value like boto
        # when not updating data.
        router.table.connection = Mock()
        router.table.connection.update_item.return_value = {}
        result = router.register_user(dict(uaid="", node_id="me",
                                           connected_at=1234))
        eq_(result[0], True)

    def test_save_fail(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection = Mock()
        router.table.connection.update_item.side_effect = raise_condition
        router_data = dict(uaid="asdf", node_id="asdf", connected_at=1234)
        result = router.register_user(router_data)
        eq_(result, (False, {}, router_data))

    def test_node_clear(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        # Register a node user
        router.register_user(dict(uaid="asdf", node_id="asdf",
                                  connected_at=1234))

        # Verify
        user = router.get_uaid("asdf")
        eq_(user["node_id"], "asdf")

        # Clear
        router.clear_node(user)

        # Verify
        user = router.get_uaid("asdf")
        eq_(user.get("node_id"), None)

    def test_node_clear_fail(self):
        r = get_router_table()
        router = Router(r, SinkMetrics())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection.put_item = Mock()
        router.table.connection.put_item.side_effect = raise_condition
        data = dict(uaid="asdf", node_id="asdf", connected_at=1234)
        result = router.clear_node(Item(r, data))
        eq_(result, False)

    def test_drop_user(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, SinkMetrics())
        # Register a node user
        router.register_user(dict(uaid=uaid, node_id="asdf",
                                  connected_at=1234))
        result = router.drop_user(uaid)
        eq_(result, True)
        # Deleting already deleted record should return false.
        result = router.drop_user(uaid)
        eq_(result, False)
