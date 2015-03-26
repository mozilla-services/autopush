import unittest
import uuid

from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ProvisionedThroughputExceededException,
)
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_

from autopush.db import (
    create_router_table,
    create_storage_table,
    get_router_table,
    get_storage_table,
    Storage,
    Router,
)


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()

    def tearDown(self):
        self.mock_dynamodb2.stop()

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

    def test_storage_table_created(self):
        # Check that the table doesn't exist
        db = DynamoDBConnection()
        dblist = db.list_tables()["TableNames"]
        assert "storage" not in dblist

        # Create the storage table
        create_storage_table()

        dblist = db.list_tables()["TableNames"]
        assert "storage" in dblist

        get_storage_table()

    def test_dont_save_older(self):
        s = get_storage_table()
        storage = Storage(s)
        # Unfortunately moto can't run condition expressions, so
        # we gotta fake it
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        storage.table.connection.put_item.side_effect = raise_error
        result = storage.save_notification("fdas",  "asdf", 8)
        eq_(result, False)

    def test_delete_over_provisioned(self):
        s = get_storage_table()
        storage = Storage(s)
        storage.table.connection = Mock()

        def raise_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        storage.table.connection.delete_item.side_effect = raise_error
        results = storage.delete_notification("asdf", "asdf")
        eq_(results, False)


class RouterTestCase(unittest.TestCase):
    def setUp(self):
        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()

    def tearDown(self):
        self.mock_dynamodb2.stop()

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

    def test_router_table_created(self):
        # Check that the table doesn't exist
        db = DynamoDBConnection()
        dblist = db.list_tables()["TableNames"]
        assert "router" not in dblist

        # Create the router table
        create_router_table()

        dblist = db.list_tables()["TableNames"]
        assert "router" in dblist
        get_router_table()

    def test_no_uaid_found(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r)
        result = router.get_uaid(uaid)
        eq_(result, False)

    def test_save_uaid(self):
        uaid = str(uuid.uuid4())
        r = get_router_table()
        router = Router(r)
        result = router.register_user(uaid, "me", 1234)
        eq_(result, True)
        result = router.get_uaid(uaid)
        eq_(bool(result), True)
        eq_(result["node_id"], "me")

    def test_save_fail(self):
        r = get_router_table()
        router = Router(r)

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection = Mock()
        router.table.connection.put_item.side_effect = raise_condition
        result = router.register_user("asdf", "asdf", 1234)
        eq_(result, False)

    def test_node_clear(self):
        r = get_router_table()
        router = Router(r)

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
        router = Router(r)

        def raise_condition(*args, **kwargs):
            raise ConditionalCheckFailedException(None, None)

        router.table.connection = Mock()
        router.table.connection.put_item.side_effect = raise_condition
        result = router.clear_node(dict(uaid="asdf", node_id="asdf",
                                        connected_at=1234))
        eq_(result, False)
