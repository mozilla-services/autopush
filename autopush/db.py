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

import json


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
            cond = "attribute_not_exists(version) or version < :ver"
            conn.put_item(
                "storage",
                item={
                    "uaid": {'S': uaid},
                    "chid": {'S': chid},
                    "version": {'N': str(version)}
                },
                condition_expression=cond,
                expression_attribute_values={
                    ":ver": {'N': str(version)}
                }
            )
            return True
        except ConditionalCheckFailedException:
            return False

    def delete_notification(self, uaid, chid, version=None):
        try:
            if version:
                self.table.delete_item(uaid=uaid, chid=chid,
                                       expected={"version__eq": version})
            else:
                self.table.delete_item(uaid=uaid, chid=chid)
            return True
        except ProvisionedThroughputExceededException:
            return False

    ## Proprietary Ping storage info
    ## Tempted to put this in own class.

    tableName = "router"
    ping_label = "proprietary_ping"
    type_label = "ping_type"
    modf_label = "modified"

    def register_connect(self, uaid, connect):
        try:
            cinfo = json.loads(connect)
            """ Register a type of proprietary ping data"""
            # Always overwrite.
            if cinfo.get("type") is None:
                return False
            self.table.connection.update_item(
                self.tableName,
                key={"uaid": {'S': uaid}},
                attribute_updates={
                    self.ping_label: {"Action": "PUT",
                                      "Value": {'S': connect}},
                }
            )
        except ProvisionedThroughputExceededException:
            return False
        except ValueError:
            #Invalid connect JSON specified, most likely.
            return False
        return True

    def get_connection(self, uaid):
        try:
            record = self.table.get_item(consistent=True,
                                         uaid=uaid)
        except ItemNotFound:
            return False
        except ProvisionedThroughputExceededException:
            return False
        return json.loads(record.get(self.ping_label))

    def unregister_connect(self, uaid):
        try:
            self.table.connection.update_item(
                self.tableName,
                key={"uaid": {'S': uaid}},
                attribute_updates={
                    self.ping_label: {"Action": "DELETE"},
                },
            )
        except ProvisionedThroughputExceededException:
            return False
        return True


class Router(object):
    def __init__(self, table):
        self.table = table

    def get_uaid(self, uaid):
        try:
            return self.table.get_item(consistent=True, uaid=uaid)
        except (ItemNotFound, JSONResponseError):
            # Under tests, this failed without catching a JSONResponseError,
            # which is weird as hell. But whatever, we'll catch that too.
            return False

    def register_user(self, uaid, node_id, connected_at):
        """Attempt to register this user if it doesn't already exist or
        this is the latest connection"""
        conn = self.table.connection
        try:
            cond = "attribute_not_exists(node_id) or (connected_at < :conn)"
            conn.put_item(
                "router",
                item={
                    "uaid": {'S': uaid},
                    "node_id": {'S': node_id},
                    "connected_at": {'N': str(connected_at)}
                },
                condition_expression=cond,
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
            cond = "(node_id = :node) and (connected_at = :conn)"
            conn.put_item(
                "router",
                item={
                    "uaid": {'S': item["uaid"]},
                    "connected_at": {'N': str(item["connected_at"])}
                },
                condition_expression=cond,
                expression_attribute_values={
                    ":node": {'S': item["node_id"]},
                    ":conn": {'N': str(item["connected_at"])}
                }
            )
            return True
        except ConditionalCheckFailedException:
            return False
