from boto.dynamodb2.fields import HashKey, KeysOnlyIndex
from boto.dynamodb2.table import Table


def create_router_table(connection):
    router = Table.create("router",
                          schema=[HashKey("uaid")],
                          throughput=dict(read=5, write=5),
                          global_indexes=[
                              KeysOnlyIndex(
                                  'AccessIndex',
                                  parts=[HashKey('last_connect')],
                                  throughput=dict(read=5, write=5))],
                          connection=connection
                          )
    return router


def create_storage_table(connection):
    storage = Table.create("storage",
                           schema=[HashKey("storage")],
                           throughput=dict(read=5, write=5),
                           connection=connection
                           )
    return storage


def router_table(connection):
    return Table("router", connection=connection)


def storage_table(connection):
    return Table("storage", connection=connection)
