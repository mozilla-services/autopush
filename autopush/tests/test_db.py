import unittest
import uuid

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
    get_router_table,
    get_storage_table,
    create_router_table,
    create_storage_table,
    preflight_check,
    Storage,
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
            router.get_uaid(dict(uaid="asdf", node_id="me",
                                 connected_at=1234))

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
                        "connected_at": "1234",
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
        result = router.register_user(dict(uaid="asdf", node_id="asdf",
                                           connected_at=1234))
        eq_(result, (False, {}))

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
