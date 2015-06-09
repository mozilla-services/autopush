import uuid

from boto.exception import JSONResponseError
from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from boto.dynamodb2.fields import HashKey, RangeKey, GlobalKeysOnlyIndex
from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.table import Table
from boto.dynamodb2.types import NUMBER, STRING


def create_router_table(tablename="router", read_throughput=5,
                        write_throughput=5):
    return Table.create(tablename,
                        schema=[HashKey("uaid")],
                        throughput=dict(read=read_throughput,
                                        write=write_throughput),
                        global_indexes=[
                            GlobalKeysOnlyIndex(
                                'AccessIndex',
                                parts=[HashKey('last_connect',
                                               data_type=NUMBER)],
                                throughput=dict(read=5, write=5))],
                        )


def create_storage_table(tablename="storage", read_throughput=5,
                         write_throughput=5):
    return Table.create(tablename,
                        schema=[HashKey("uaid"), RangeKey("chid")],
                        throughput=dict(read=read_throughput,
                                        write=write_throughput),
                        # Some bridge protocols only return tokens for things
                        # like feedback or error reporting.
                        # Need an index to search for records by them.
                        global_indexes=[
                            GlobalKeysOnlyIndex(
                                'BridgeTokenIndex',
                                parts=[HashKey('bridge_token',
                                               data_type=STRING)],
                                throughput=dict(read=1, write=1))]
                        )


def router_table(tablename="router"):
    return Table(tablename)


def storage_table(tablename="storage"):
    return Table(tablename)


def get_router_table(tablename="router", read_throughput=5,
                     write_throughput=5):
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    if tablename not in dblist:
        return create_router_table(tablename, read_throughput,
                                   write_throughput)
    else:
        return router_table(tablename)


def get_storage_table(tablename="storage", read_throughput=5,
                      write_throughput=5):
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    if tablename not in dblist:
        return create_storage_table(tablename, read_throughput,
                                    write_throughput)
    else:
        return storage_table(tablename)


def preflight_check(storage, router):
    """Performs a pre-flight check of the storage/router to ensure appropriate
    permissions for operation.

    Failure to run correctly will raise an exception.

    """
    uaid = str(uuid.uuid4())
    chid = str(uuid.uuid4())
    node_id = "mynode:2020"
    connected_at = 0
    version = 12

    # Store a notification, fetch it, delete it
    storage.save_notification(uaid, chid, version)
    notifs = storage.fetch_notifications(uaid)
    assert len(notifs) > 0
    storage.delete_notification(uaid, chid, version)

    # Store a router entry, fetch it, delete it
    router.register_user(dict(uaid=uaid, node_id=node_id,
                              connected_at=connected_at))
    item = router.get_uaid(uaid)
    assert item.get("node_id") == node_id
    router.clear_node(item)


class Storage(object):
    def __init__(self, table, metrics):
        self.table = table
        self.metrics = metrics
        self.encode = table._encode_keys

    def fetch_notifications(self, uaid):
        try:
            notifs = self.table.query_2(consistent=True, uaid__eq=uaid,
                                        chid__gt=" ")
            return list(notifs)
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.fetch_notifications")
            raise

    def save_notification(self, uaid, chid, version):
        conn = self.table.connection
        try:
            cond = "attribute_not_exists(version) or version < :ver"
            conn.put_item(
                self.table.table_name,
                item=self.encode(dict(uaid=uaid, chid=chid, version=version)),
                condition_expression=cond,
                expression_attribute_values={
                    ":ver": {'N': str(version)}
                }
            )
            return True
        except ConditionalCheckFailedException:
            return False
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.save_notification")
            raise

    def delete_notification(self, uaid, chid, version=None):
        try:
            if version:
                self.table.delete_item(uaid=uaid, chid=chid,
                                       expected={"version__eq": version})
            else:
                self.table.delete_item(uaid=uaid, chid=chid)
            return True
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.delete_notification")
            return False


class Router(object):
    def __init__(self, table, metrics):
        self.table = table
        self.metrics = metrics
        self.encode = table._encode_keys

    def get_uaid(self, uaid):
        try:
            return self.table.get_item(consistent=True, uaid=uaid)
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.get_uaid")
            raise
        except JSONResponseError:
            # We trap JSONResponseError because Moto returns text instead of
            # JSON when looking up values in empty tables. We re-throw the
            # correct ItemNotFound exception
            raise ItemNotFound("uaid not found")

    def register_user(self, item):
        """Attempt to register this user if it doesn't already exist or
        this is the latest connection"""
        conn = self.table.connection
        try:
            cond = "attribute_not_exists(node_id) or (connected_at < :conn)"
            result = conn.put_item(
                self.table.table_name,
                item=self.encode(item),
                condition_expression=cond,
                expression_attribute_values=self.encode({
                    ":conn": item["connected_at"]
                }),
                return_values="ALL_OLD",
            )
            if "Attributes" in result:
                r = {}
                for key, value in result["Attributes"].items():
                    try:
                        r[key] = self.table._dynamizer.decode(value)
                    except AttributeError:
                        r[key] = value
                result = r
            return (True, result)
        except ConditionalCheckFailedException:
            return (False, {})
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.register_user")
            raise

    def clear_node(self, item):
        """Given a router item, remove the node_id from it."""
        conn = self.table.connection
        # Pop out the node_id
        node_id = item["node_id"]
        del item["node_id"]

        try:
            cond = "(node_id = :node) and (connected_at = :conn)"
            conn.put_item(
                self.table.table_name,
                item=item.get_raw_keys(),
                condition_expression=cond,
                expression_attribute_values=self.encode({
                    ":node": node_id,
                    ":conn": item["connected_at"],
                }),
            )
            return True
        except ConditionalCheckFailedException:
            return False
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.clear_node")
            raise
