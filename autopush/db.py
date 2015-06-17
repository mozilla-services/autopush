"""Database Interaction"""
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
from boto.dynamodb2.types import NUMBER


def create_router_table(tablename="router", read_throughput=5,
                        write_throughput=5):
    """Create a new router table"""
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
    """Create a new storage table for simplepush style notification storage"""
    return Table.create(tablename,
                        schema=[HashKey("uaid"), RangeKey("chid")],
                        throughput=dict(read=read_throughput,
                                        write=write_throughput),
                        )


def get_router_table(tablename="router", read_throughput=5,
                     write_throughput=5):
    """Get the main router table object

    Creates the table if it doesn't already exist, otherwise returns the
    existing table

    """
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    if tablename not in dblist:
        return create_router_table(tablename, read_throughput,
                                   write_throughput)
    else:
        return Table(tablename)


def get_storage_table(tablename="storage", read_throughput=5,
                      write_throughput=5):
    """Get the main storage table object

    Creates the table if it doesn't already exist, otherwise returns the
    existing table

    """
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    if tablename not in dblist:
        return create_storage_table(tablename, read_throughput,
                                    write_throughput)
    else:
        return Table(tablename)


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
    """Create a Storage table abstraction on top of a DynamoDB Table object"""
    def __init__(self, table, metrics):
        """Create a new Storage object

        :param table: :class:`Table` object
        :param metrics: Metrics object that implements the
                        :class:`autopush.metrics.IMetrics` interface.

        """
        self.table = table
        self.metrics = metrics
        self.encode = table._encode_keys

    def fetch_notifications(self, uaid):
        """Fetch all notifications for a UAID

        :raises:
            :exc:`ProvisionedThroughputExceededException` if dynamodb table
            exceeds throughput.

        """
        try:
            notifs = self.table.query_2(consistent=True, uaid__eq=uaid,
                                        chid__gt=" ")
            return list(notifs)
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.fetch_notifications")
            raise

    def save_notification(self, uaid, chid, version):
        """Save a notification for the UAID

        :raises:
            :exc:`ProvisionedThroughputExceededException` if dynamodb table
            exceeds throughput.

        """
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
        """Delete a notification for a UAID

        :returns: Whether or not the notification was able to be deleted.
        :rtype: bool

        """
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
    """Create a Router table abstraction on top of a DynamoDB Table object"""
    def __init__(self, table, metrics):
        """Create a new Router object

        :param table: :class:`Table` object
        :param metrics: Metrics object that implements the
                        :class:`autopush.metrics.IMetrics` interface.

        """
        self.table = table
        self.metrics = metrics
        self.encode = table._encode_keys

    def get_uaid(self, uaid):
        """Get the database record for the UAID

        :returns: User item
        :rtype: :class:`~boto.dynamodb2.items.Item`
        :raises:
            :exc:`ItemNotFound` if there is no record for this UAID.
            :exc:`ProvisionedThroughputExceededException` if dynamodb table
            exceeds throughput.

        """
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

    def register_user(self, data):
        """Attempt to register this user if it doesn't already exist or
        this is the latest connection.

        If a record exists with a newer ``connected_at``, then the user will
        not be registered.

        :returns: Whether the user was registered or not.
        :rtype: bool
        :raises:
            :exc:`ProvisionedThroughputExceededException` if dynamodb table
            exceeds throughput.

        """
        conn = self.table.connection
        db_key = self.encode({"uaid": data.pop("uaid")})
        # Generate our update expression
        expr = "SET " + ", ".join(["%s=:%s" % (x, x) for x in data.keys()])
        expr_values = self.encode({":%s" % k: v for k, v in data.items()})
        try:
            cond = " or ".join([
                "attribute_not_exists(node_id)",
                "(connected_at < :connected_at)",
            ])
            result = conn.update_item(
                self.table.table_name,
                db_key,
                update_expression=expr,
                condition_expression=cond,
                expression_attribute_values=expr_values,
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
        """Given a router item, remove the node_id from it.

        The node_id will only be cleared if the ``connected_at`` matches up
        with the item's ``connected_at``.

        :returns: Whether the node was cleared or not.
        :rtype: bool
        :raises:
            :exc:`ProvisionedThroughputExceededException` if dynamodb table
            exceeds throughput.

        """
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
