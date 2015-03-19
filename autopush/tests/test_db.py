import unittest

from boto.dynamodb2.layer1 import DynamoDBConnection
from moto import mock_dynamodb2

from autopush.db import (
    create_router_table,
    create_storage_table,
    router_table,
    storage_table,
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
