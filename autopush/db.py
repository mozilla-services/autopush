"""Database Interaction

WebPush Sort Keys
-----------------

Messages for WebPush are stored using a partition key + sort key, originally
the sort key was:

    CHID : Encrypted(UAID: CHID)

The encrypted portion was returned as the Location to the Application Server.
Decrypting it resulted in enough information to create the sort key so that
the message could be deleted and located again.

For WebPush Topic messages, a new scheme was needed since the only way to
locate the prior message is the UAID + CHID + Topic. Using Encryption in
the sort key is therefore not useful since it would change every update.

The sort key scheme for WebPush messages is:

    VERSION : CHID : TOPIC

To ensure updated messages are not deleted, each message will still have an
update-id key/value in its item.

Non-versioned messages are assumed to be original messages from before this
scheme was adopted.

``VERSION`` is a 2-digit 0-padded number, starting at 01 for Topic messages.

"""
from __future__ import absolute_import

import datetime
import random
import time
import uuid
from functools import wraps

from boto.exception import JSONResponseError, BotoServerError
from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from boto.dynamodb2.fields import HashKey, RangeKey, GlobalKeysOnlyIndex
from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.table import Table, Item
from boto.dynamodb2.types import NUMBER
from typing import Iterable, List  # flake8: noqa

from autopush.exceptions import AutopushException
from autopush.utils import (
    generate_hash,
    normalize_id,
    WebPushNotification,
)

key_hash = ""
TRACK_DB_CALLS = False
DB_CALLS = []


def get_month(delta=0):
    """Basic helper function to get a datetime.date object iterations months
    ahead/behind of now.

    :type delta: int

    :rtype: datetime.datetime

    """
    new = last = datetime.date.today()
    # Move until we hit a new month, this avoids having to manually
    # check year changes as we push forward or backward since the Python
    # timedelta math handles it for us
    for _ in range(abs(delta)):
        while new.month == last.month:
            if delta < 0:
                new -= datetime.timedelta(days=14)
            else:
                new += datetime.timedelta(days=14)
        last = new
    return new


def hasher(uaid):
    if key_hash:
        return generate_hash(key_hash, uaid)
    return uaid


def dump_uaid(uaid_data):
    """Return a dict for a uaid.

    This is utilized instead of repr since some db methods return a
    DynamoDB Item which does not actually show its dict key/values
    when dumped via repr.

    """
    if isinstance(uaid_data, Item):
        return repr(uaid_data.items())
    else:
        return repr(uaid_data)


def make_rotating_tablename(prefix, delta=0, date=None):
    """Creates a tablename for table rotation based on a prefix with a given
    month delta."""
    if not date:
        date = get_month(delta=delta)
    return "{}_{}_{}".format(prefix, date.year, date.month)


def create_rotating_message_table(prefix="message", read_throughput=5,
                                  write_throughput=5, delta=0):
    """Create a new message table for webpush style message storage"""
    tablename = make_rotating_tablename(prefix, delta)
    return Table.create(tablename,
                        schema=[HashKey("uaid"),
                                RangeKey("chidmessageid")],
                        throughput=dict(read=read_throughput,
                                        write=write_throughput),
                        )


def get_rotating_message_table(prefix="message", delta=0, date=None,
                               message_read_throughput=5,
                               message_write_throughput=5):
    """Gets the message table for the current month."""
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    tablename = make_rotating_tablename(prefix, delta, date)
    if tablename not in dblist:
        return create_rotating_message_table(
            prefix=prefix, delta=delta,
            read_throughput=message_read_throughput,
            write_throughput=message_write_throughput)
    else:
        return Table(tablename)


def create_router_table(tablename="router", read_throughput=5,
                        write_throughput=5):
    """Create a new router table

    The last_connect index is a value used to determine the last month a user
    was seen in. To prevent hot-keys on this table during month switchovers the
    key is determined based on the following scheme:

        (YEAR)(MONTH)(DAY)(HOUR)(0001-0010)

    Note that the random key is only between 1-10 at the moment, if the key is
    still too hot during production the random range can be increased at the
    cost of additional queries during GC to locate expired users.

    """
    return Table.create(tablename,
                        schema=[HashKey("uaid")],
                        throughput=dict(read=read_throughput,
                                        write=write_throughput),
                        global_indexes=[
                            GlobalKeysOnlyIndex(
                                'AccessIndex',
                                parts=[
                                    HashKey('last_connect',
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


def _make_table(table_func, tablename, read_throughput, write_throughput):
    """Private common function to make a table with a table func"""
    db = DynamoDBConnection()
    dblist = db.list_tables()["TableNames"]
    if tablename not in dblist:
        return table_func(tablename, read_throughput, write_throughput)
    else:
        return Table(tablename)


def get_router_table(tablename="router", read_throughput=5,
                     write_throughput=5):
    """Get the main router table object

    Creates the table if it doesn't already exist, otherwise returns the
    existing table.

    """
    return _make_table(create_router_table, tablename, read_throughput,
                       write_throughput)


def get_storage_table(tablename="storage", read_throughput=5,
                      write_throughput=5):
    """Get the main storage table object

    Creates the table if it doesn't already exist, otherwise returns the
    existing table.

    """
    return _make_table(create_storage_table, tablename, read_throughput,
                       write_throughput)


def preflight_check(storage, router, uaid="deadbeef00000000deadbeef00000000"):
    """Performs a pre-flight check of the storage/router/message to ensure
    appropriate permissions for operation.

    Failure to run correctly will raise an exception.

    """
    # Verify tables are ready for use if they just got created
    ready = False
    while not ready:
        tbl_status = [x.describe()["Table"]["TableStatus"]
                      for x in [storage.table, router.table]]
        ready = all([status == "ACTIVE" for status in tbl_status])
        if not ready:
            time.sleep(1)

    # Use a distinct UAID so it doesn't interfere with metrics
    chid = uuid.uuid4().hex
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
                              connected_at=connected_at,
                              router_type="simplepush"))
    item = router.get_uaid(uaid)
    assert item.get("node_id") == node_id
    # Clean up the preflight data.
    router.clear_node(item)
    router.drop_user(uaid)
    storage.table.delete_item(uaid=uaid, chid=chid)
    storage.table.delete_item(uaid=uaid, chid=" ")


def track_provisioned(func):
    """Tracks provisioned exceptions and increments a metric for them named
    after the function decorated"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if TRACK_DB_CALLS:
            DB_CALLS.append(func.__name__)
        try:
            return func(self, *args, **kwargs)
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.%s" % func.__name__)
            raise
        except BotoServerError:
            self.metrics.increment("error.botoserver.%s" % func.__name__)
            raise
    return wrapper


def has_connected_this_month(item):
    """Whether or not a router item has connected this month

    :type item: dict

    :rtype: bool

    """
    last_connect = item.get("last_connect")
    if not last_connect:
        return False

    today = datetime.datetime.today()
    val = "%s%s" % (today.year, str(today.month).zfill(2))
    return str(last_connect).startswith(val)


def generate_last_connect():
    """Generate a last_connect

    This intentionally generates a limited set of keys for each month in a
    known sequence. For each month, there's 24 hours * 10 random numbers for
    a total of 240 keys per month depending on when the user migrates forward.

    :type date: datetime.datetime

    :rtype: int

    """
    today = datetime.datetime.today()
    val = "".join([
        str(today.year),
        str(today.month).zfill(2),
        str(today.hour).zfill(2),
        str(random.randint(0, 10)).zfill(4),
    ])
    return int(val)


def generate_last_connect_values(date):
    """Generator of last_connect values for a given date

    Creates an iterator that yields all the valid values for ``last_connect``
    for a given year/month.

    :type date: datetime.datetime

    :rtype: Iterable[int]

    """
    year = str(date.year)
    month = str(date.month).zfill(2)
    for hour in range(0, 24):
        for rand_int in range(0, 11):
            val = "".join([year, month, str(hour).zfill(2),
                           str(rand_int).zfill(4)])
            yield int(val)


class Storage(object):
    """Create a Storage table abstraction on top of a DynamoDB Table object"""
    def __init__(self, table, metrics):
        """Create a new Storage object

        :param table: :class:`Table` object.
        :param metrics: Metrics object that implements the
                        :class:`autopush.metrics.IMetrics` interface.

        """
        self.table = table
        self.metrics = metrics
        self.encode = table._encode_keys

    @track_provisioned
    def fetch_notifications(self, uaid):
        """Fetch all notifications for a UAID

        :raises:
            :exc:`ProvisionedThroughputExceededException` if dynamodb table
            exceeds throughput.

        """
        notifs = self.table.query_2(consistent=True, uaid__eq=hasher(uaid),
                                    chid__gt=" ")
        return list(notifs)

    @track_provisioned
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
                item=self.encode(dict(uaid=hasher(uaid),
                                      chid=normalize_id(chid),
                                      version=version)),
                condition_expression=cond,
                expression_attribute_values={
                    ":ver": {'N': str(version)}
                }
            )
            return True
        except ConditionalCheckFailedException:
            return False

    def delete_notification(self, uaid, chid, version=None):
        """Delete a notification for a UAID

        :returns: Whether or not the notification was able to be deleted.
        :rtype: bool

        """
        try:
            if version:
                self.table.delete_item(uaid=hasher(uaid),
                                       chid=normalize_id(chid),
                                       expected={"version__eq": version})
            else:
                self.table.delete_item(uaid=hasher(uaid),
                                       chid=normalize_id(chid))
            return True
        except ProvisionedThroughputExceededException:
            self.metrics.increment("error.provisioned.delete_notification")
            return False


class Message(object):
    """Create a Message table abstraction on top of a DynamoDB Table object"""
    def __init__(self, table, metrics):
        """Create a new Message object

        :param table: :class:`Table` object.
        :param metrics: Metrics object that implements the
                        :class:`autopush.metrics.IMetrics` interface.

        """
        self.table = table
        self.metrics = metrics
        self.encode = table._encode_keys

    @track_provisioned
    def register_channel(self, uaid, channel_id):
        """Register a channel for a given uaid"""
        conn = self.table.connection
        db_key = self.encode({"uaid": hasher(uaid), "chidmessageid": " "})
        # Generate our update expression
        expr = "ADD chids :channel_id"
        expr_values = self.encode({":channel_id":
                                  set([normalize_id(channel_id)])})
        conn.update_item(
            self.table.table_name,
            db_key,
            update_expression=expr,
            expression_attribute_values=expr_values,
        )
        return True

    @track_provisioned
    def unregister_channel(self, uaid, channel_id, **kwargs):
        """Remove a channel registration for a given uaid"""
        conn = self.table.connection
        db_key = self.encode({"uaid": hasher(uaid), "chidmessageid": " "})
        expr = "DELETE chids :channel_id"
        expr_values = self.encode({":channel_id":
                                   set([normalize_id(channel_id)])})

        result = conn.update_item(
            self.table.table_name,
            db_key,
            update_expression=expr,
            expression_attribute_values=expr_values,
            return_values="UPDATED_OLD",
        )
        chids = result.get('Attributes', {}).get('chids', {})
        if chids:
            try:
                return channel_id in self.table._dynamizer.decode(chids)
            except (TypeError, AttributeError):  # pragma: nocover
                pass
        # if, for some reason, there are no chids defined, return False.
        return False

    @track_provisioned
    def all_channels(self, uaid):
        """Retrieve a list of all channels for a given uaid"""

        # Note: This only returns the chids associated with the UAID.
        # Functions that call store_message() would be required to
        # update that list as well using register_channel()
        try:
            result = self.table.get_item(consistent=True, uaid=hasher(uaid),
                                         chidmessageid=" ")
            return (True, result["chids"] or set([]))
        except ItemNotFound:
            return False, set([])

    @track_provisioned
    def save_channels(self, uaid, channels):
        """Save out a set of channels"""
        self.table.put_item(data=dict(
            uaid=hasher(uaid),
            chidmessageid=" ",
            chids=channels
        ), overwrite=True)

    @track_provisioned
    def store_message(self, notification):
        """Stores a WebPushNotification in the message table

        :type notification: WebPushNotification
        :type timestamp: int

        """
        item = dict(
            uaid=hasher(notification.uaid.hex),
            chidmessageid=notification.sort_key,
            data=notification.data,
            headers=notification.headers,
            ttl=notification.ttl,
            timestamp=notification.timestamp,
            updateid=notification.update_id
        )
        self.table.put_item(data=item, overwrite=True)
        return True

    @track_provisioned
    def delete_message(self, notification):
        """Deletes a specific message

        :type notification: WebPushNotification

        """
        if notification.update_id:
            try:
                self.table.delete_item(
                    uaid=hasher(notification.uaid.hex),
                    chidmessageid=notification.sort_key,
                    expected={'updateid__eq': notification.update_id})
            except ConditionalCheckFailedException:
                return False
        else:
            self.table.delete_item(
                uaid=hasher(notification.uaid.hex),
                chidmessageid=notification.sort_key,
            )
        return True

    @track_provisioned
    def fetch_messages(self, uaid, limit=10):
        """Fetches messages for a uaid

        :type uaid: uuid.UUID
        :type limit: int

        """
        # Eagerly fetches all results in the result set.
        results = list(self.table.query_2(uaid__eq=hasher(uaid.hex),
                                          chidmessageid__gt=" ",
                                          consistent=True, limit=limit))
        return [
            WebPushNotification.from_message_table(uaid, x) for x in results
        ]


class Router(object):
    """Create a Router table abstraction on top of a DynamoDB Table object"""
    def __init__(self, table, metrics):
        """Create a new Router object

        :param table: :class:`Table` object.
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
            item = self.table.get_item(consistent=True, uaid=hasher(uaid))
            if item.keys() == ['uaid']:
                # Incomplete record, drop it.
                self.drop_user(uaid)
                raise ItemNotFound("uaid not found")
            return item
        except ProvisionedThroughputExceededException:
            # We unfortunately have to catch this here, as track_provisioned
            # will not see this, since JSONResponseError is a subclass and
            # will capture it
            self.metrics.increment("error.provisioned.get_uaid")
            raise
        except JSONResponseError:  # pragma: nocover
            # We trap JSONResponseError because Moto returns text instead of
            # JSON when looking up values in empty tables. We re-throw the
            # correct ItemNotFound exception
            raise ItemNotFound("uaid not found")

    @track_provisioned
    def register_user(self, data):
        """Register this user

        If a record exists with a newer ``connected_at``, then the user will
        not be registered.

        :returns: Whether the user was registered or not.
        :rtype: tuple
        :raises:
            :exc:`ProvisionedThroughputExceededException` if dynamodb table
            exceeds throughput.

        """
        # Fetch a senderid for this user
        conn = self.table.connection
        db_key = self.encode({"uaid": hasher(data["uaid"])})
        del data["uaid"]
        if "router_type" not in data or "connected_at" not in data:
            # Not specifying these values will generate an exception in AWS.
            raise AutopushException("data is missing router_type "
                                    "or connected_at")
        # Generate our update expression
        expr = "SET " + ", ".join(["%s=:%s" % (x, x) for x in data.keys()])
        expr_values = self.encode({":%s" % k: v for k, v in data.items()})
        try:
            cond = """(
                attribute_not_exists(router_type) or
                (router_type = :router_type)
            ) and (
                attribute_not_exists(node_id) or
                (connected_at < :connected_at)
            )"""
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
                    except (TypeError, AttributeError):  # pragma: nocover
                        # Included for safety as moto has occasionally made
                        # this not work
                        r[key] = value
                result = r
            return (True, result, data)
        except ConditionalCheckFailedException:
            return (False, {}, data)

    @track_provisioned
    def drop_user(self, uaid):
        # The following hack ensures that only uaids that exist and are
        # deleted return true.
        huaid = hasher(uaid)
        return self.table.delete_item(uaid=huaid,
                                      expected={"uaid__eq": huaid})

    def delete_uaids(self, uaids):
        """Issue a batch delete call for the given uaids

        :type uaids: List[str]

        """
        with self.table.batch_write() as batch:
            for uaid in uaids:
                batch.delete_item(uaid=uaid)

    def drop_old_users(self, months_ago=2):
        """Drops user records that have no recent connection

        Utilizes the last_connect index to locate users that haven't
        connected in the given time-frame.

        The caller must iterate through this generator to trigger batch
        delete calls. Caller should wait as appropriate to avoid exceeding
        table limits.

        Each iteration will result in a batch delete for the currently
        iterated batch. This implies a set of writes equal in size to the
        ``25 * record-size`` minimum.

        .. warning::

            Calling list() on this generator will likely exceed provisioned
            write through-put as the batch-delete calls will be made as
            quickly as possible.

        :param months_ago: how many months ago since the last connect
        :type months_ago: int

        :returns: Iterable of how many deletes were run
        :rtype: Iterable[int]

        """
        prior_date = get_month(-months_ago)

        batched = []
        for hash_key in generate_last_connect_values(prior_date):
            result_set = self.table.query_2(
                last_connect__eq=hash_key,
                index="AccessIndex",
            )
            for result in result_set:
                batched.append(result["uaid"])

                if len(batched) == 25:
                    self.delete_uaids(batched)
                    batched = []
                    yield 25

        # Delete any leftovers
        if batched:
            self.delete_uaids(batched)
            yield len(batched)

    @track_provisioned
    def update_message_month(self, uaid, month):
        """Update the route tables current_message_month

        Note that we also update the last_connect at this point since webpush
        users when connecting will always call this once that month.

        """
        conn = self.table.connection
        db_key = self.encode({"uaid": hasher(uaid)})
        expr = "SET current_month=:curmonth, last_connect=:last_connect"
        expr_values = self.encode({":curmonth": month,
                                   ":last_connect": generate_last_connect()
                                   })
        conn.update_item(
            self.table.table_name,
            db_key,
            update_expression=expr,
            expression_attribute_values=expr_values,
        )
        return True

    @track_provisioned
    def clear_node(self, item):
        """Given a router item and remove the node_id

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
                item=self.encode(item),
                condition_expression=cond,
                expression_attribute_values=self.encode({
                    ":node": node_id,
                    ":conn": item["connected_at"],
                }),
            )
            return True
        except ConditionalCheckFailedException:
            return False
