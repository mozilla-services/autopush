from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from boto.dynamodb2.fields import HashKey, RangeKey, GlobalKeysOnlyIndex
from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.table import Table
from boto.dynamodb2.types import NUMBER


def create_router_table():
    return Table.create("router",
                        schema=[HashKey("uaid")],
                        throughput=dict(read=5, write=5),
                        global_indexes=[
                            GlobalKeysOnlyIndex(
                                'AccessIndex',
                                parts=[HashKey('last_connect',
                                               data_type=NUMBER)],
                                throughput=dict(read=5, write=5))],
                        )


def create_storage_table():
    return Table.create("storage",
                        schema=[HashKey("uaid"), RangeKey("chid")],
                        throughput=dict(read=5, write=5),
                        )


def router_table():
    return Table("router")


def storage_table():
    return Table("storage")


def get_router_table():
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    if "router" not in dblist:
        return create_router_table()
    else:
        return router_table()


def get_storage_table():
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    if "storage" not in dblist:
        return create_storage_table()
    else:
        return storage_table()


class Storage(object):
    def __init__(self, table):
        self.table = table

    def fetch_notifications(self, uaid):
        notifs = self.table.query_2(consistent=True, uaid__eq=uaid,
                                    chid__gt=" ")
        return list(notifs)

    def save_notification(self, uaid, chid, version):
        conn = self.table.connection
        try:
            conn.put_item(
                "storage",
                item={
                    "uaid": {'S': uaid},
                    "chid": {'S': chid},
                    "version": {'N': str(version)}
                },
                condition_expression=
                "attribute_not_exists(version) or version < :ver",
                expression_attribute_values={
                    ":ver": {'N': str(version)}
                }
            )
            return True
        except ConditionalCheckFailedException:
            return False

    def delete_notification(self, uaid, chid, version=None):
        if version:
            return self.table.delete_item(uaid=uaid, chid=chid,
                                          expected={"version__eq": version})
        else:
            return self.table.delete_item(uaid=uaid, chid=chid)


class Router(object):
    def __init__(self, table):
        self.table = table

    def get_uaid(self, uaid):
        try:
            return self.table.get_item(consistent=True, uaid=uaid)
        except ItemNotFound:
            return False

    def register_user(self, uaid, node_id, connected_at):
        """Attempt to register this user if it doesn't already exist or
        this is the latest connection"""
        conn = self.table.connection
        try:
            conn.put_item(
                "router",
                item={
                    "uaid": {'S': uaid},
                    "node_id": {'S': node_id},
                    "connected_at": {'N': str(connected_at)}
                },
                condition_expression=
                "attribute_not_exists(node_id) or (connected_at < :conn)",
                expression_attribute_values={
                    ":conn": {'N': str(connected_at)}
                }
            )
            return True
        except ConditionalCheckFailedException:
            return False

    def clear_node(self, item):
        """Given a router item, remove the node_id from it."""
        conn = self.table.connection
        try:
            conn.put_item(
                "router",
                item={
                    "uaid": {'S': item["uaid"]},
                    "connected_at": {'N': str(item["connected_at"])}
                },
                condition_expression=
                "(node_id = :node) and (connected_at = :conn)",
                expression_attribute_values={
                    ":node": {'S': item["node_id"]},
                    ":conn": {'N': str(item["connected_at"])}
                }
            )
            return True
        except ConditionalCheckFailedException:
            return False

    def update_uaid(self, uaid, node_id, connected_at):
        conn = self.table.connection
        try:
            conn.put_item(
                "router",
                item={
                    "uaid": {'S': uaid},
                    "node_id": {'S': node_id},
                    "connected_at": {'N': str(connected_at)}
                },
                condition_expression=
                "connected_at < :conn",
                expression_attribute_values={
                    ":conn": {'N': str(connected_at)}
                }
            )
        except ConditionalCheckFailedException:
            return False
