import unittest
import uuid

from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ProvisionedThroughputExceededException,
    ItemNotFound,
)
from boto.dynamodb2.layer1 import DynamoDBConnection
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_

from autopush.db import (
    get_router_table,
    get_storage_table,
    create_router_table,
    create_storage_table,
    preflight_check,
    Storage,
    Router,
)
from autopush.settings import MetricSink


mock_db2 = mock_dynamodb2()


def setUp():
    mock_db2.start()


def tearDown():
    mock_db2.stop()


class DbCheckTestCase(unittest.TestCase):
    def test_preflight_check(self):
        router_table = get_router_table()
        storage_table = get_storage_table()

        def raise_exc(*args, **kwargs):
            raise Exception("Oops")

        router_table.clear_node = Mock()
        router_table.clear_node.side_effect = raise_exc

        with self.assertRaises(Exception):
            preflight_check(storage_table, router_table)


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
        assert s.throughput["read"] is 8
        assert s.throughput["write"] is 11

    def test_dont_save_older(self):
        s = get_storage_table()
        storage = Storage(s, MetricSink())
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
        storage = Storage(s, MetricSink())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.put_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            storage.save_notification("asdf", "asdf", 12)

    def test_save_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, MetricSink())
        storage.table = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.query_2.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            storage.fetch_notifications("asdf")

    def test_delete_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s, MetricSink())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.delete_item.side_effect = raise_error
        results = storage.delete_notification("asdf", "asdf")
        eq_(results, False)

    def test_register_connect(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table.connection = Mock()

        # try bad connect data:
        self.assertRaises(ValueError, storage.register_connect,
                          "uaid", {})

        # try bad connect data:
        self.assertRaises(ValueError, storage.register_connect,
                          "uaid", {"notype": "test"})

        # try minimal correct data
        self.assertRaises(None, storage.register_connect("uaid",
                          {"type": "test"}))

    def test_register_connect_over(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.update_item.side_effect = raise_error
        self.assertRaises(ProvisionedThroughputExceededException,
                          storage.register_connect, "uaid", {"type": "test"})

    def test_unregister_connect(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table.connection = Mock()
        result = storage.unregister_connect("uaid")
        self.assertTrue(result)

    def test_unregister_connect_over(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.update_item.side_effect = raise_error
        results = storage.unregister_connect("uaid")
        eq_(results, False)

    def test_get_connection(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table = Mock()
        storage.table.get_item.return_value = \
            {"proprietary_ping": '{"type":"test"}'}

        result = storage.get_connection('uaid')
        eq_(result, {'type': 'test'})

        def raise_error(*args, **kwargs):
            raise ItemNotFound(None, None)

        storage.table.get_item.side_effect = raise_error
        result = storage.get_connection('uaid')
        eq_(result, False)

    def test_get_connection_over(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.get_item.side_effect = raise_error
        results = storage.get_connection("uaid")
        eq_(results, False)

    def test_byToken_delete(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table.connection = Mock()
        result = storage.byToken('DELETE', 'abc123')
        eq_(result, True)

    def test_byToken_update(self):
        storage = Storage(get_storage_table(), MetricSink())
        storage.table = Mock()
        storage.table.connection = Mock()
        storage.table.connection.update_item.return_value
        storage.table.get_item.return_value = \
            {"uaid": "test",
             "proprietary_ping":
             '{"type": "test", "token": "old123"}'}
        result = storage.byToken('UPDATE', 'new456')
        eq_(result, True)


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
        assert r.throughput["read"] is 3
        assert r.throughput["write"] is 17

    def test_no_uaid_found(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, MetricSink())
        result = router.get_uaid(uaid)
        eq_(result, False)

    def test_uaid_provision_failed(self):
        r = get_router_table()
        router = Router(r, MetricSink())
        router.table = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.get_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            router.get_uaid("asdf")

    def test_register_user_provision_failed(self):
        r = get_router_table()
        router = Router(r, MetricSink())
        router.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.put_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            router.register_user("asdf", "asdf", 12)

    def test_clear_node_provision_failed(self):
        r = get_router_table()
        router = Router(r, MetricSink())
        router.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        router.table.connection.put_item.side_effect = raise_error
        with self.assertRaises(ProvisionedThroughputExceededException):
            router.clear_node(dict(uaid="asdf", connected_at="1234",
                                   node_id="asdf"))

    def test_save_uaid(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r, MetricSink())
        result = router.register_user(uaid, "me", 1234)
        eq_(bool(result), True)
        result = router.get_uaid(uaid)
        eq_(bool(result), True)
        eq_(result["node_id"], "me")

    def test_save_fail(self):
        r = get_router_table()
        router = Router(r, MetricSink())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection = Mock()
        router.table.connection.put_item.side_effect = raise_condition
        result = router.register_user("asdf", "asdf", 1234)
        eq_(result, False)

    def test_node_clear(self):
        r = get_router_table()
        router = Router(r, MetricSink())

        # Register a node user
        router.register_user("asdf", "asdf", 1234)

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
        router = Router(r, MetricSink())

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection = Mock()
        router.table.connection.put_item.side_effect = raise_condition
        result = router.clear_node(dict(uaid="asdf", node_id="asdf",
                                        connected_at=1234))
        eq_(result, False)
