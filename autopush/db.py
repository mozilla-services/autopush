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

from attr import (
    asdict,
    attrs,
    attrib,
    Factory
)
from boto.exception import JSONResponseError
from boto.dynamodb2.exceptions import (
    ConditionalCheckFailedException,
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from boto.dynamodb2.fields import HashKey, RangeKey, GlobalKeysOnlyIndex
from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2.table import Table, Item
from boto.dynamodb2.types import NUMBER
from typing import (  # noqa
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    TypeVar,
    Tuple,
)
from twisted.internet.defer import Deferred  # noqa
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads import deferToThread

import autopush.metrics
from autopush.exceptions import AutopushException
from autopush.metrics import IMetrics  # noqa
from autopush.types import ItemLike  # noqa
from autopush.utils import (
    generate_hash,
    normalize_id,
    WebPushNotification,
)

if TYPE_CHECKING:  # pragma: nocover
    from autopush.config import AutopushConfig, DDBTableConfig  # noqa


# Typing
T = TypeVar('T')  # noqa

key_hash = ""
TRACK_DB_CALLS = False
DB_CALLS = []


def get_month(delta=0):
    # type: (int) -> datetime.date
    """Basic helper function to get a datetime.date object iterations months
    ahead/behind of now.

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
    # type: (str) -> str
    """Hashes a key using a key_hash if present"""
    if key_hash:
        return generate_hash(key_hash, uaid)
    return uaid


def dump_uaid(uaid_data):
    # type: (ItemLike) -> str
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
    # type: (str, int, Optional[datetime.date]) -> str
    """Creates a tablename for table rotation based on a prefix with a given
    month delta."""
    if not date:
        date = get_month(delta=delta)
    return "{}_{:04d}_{:02d}".format(prefix, date.year, date.month)


def create_rotating_message_table(prefix="message", delta=0, date=None,
                                  read_throughput=5,
                                  write_throughput=5):
    # type: (str, int, Optional[datetime.date], int, int) -> Table
    """Create a new message table for webpush style message storage"""
    tablename = make_rotating_tablename(prefix, delta, date)
    return Table.create(tablename,
                        schema=[HashKey("uaid"),
                                RangeKey("chidmessageid")],
                        throughput=dict(read=read_throughput,
                                        write=write_throughput),
                        )


def get_rotating_message_table(prefix="message", delta=0, date=None,
                               message_read_throughput=5,
                               message_write_throughput=5):
    # type: (str, int, Optional[datetime.date], int, int) -> Table
    """Gets the message table for the current month."""
    tablename = make_rotating_tablename(prefix, delta, date)
    if not table_exists(DynamoDBConnection(), tablename):
        return create_rotating_message_table(
            prefix=prefix, delta=delta, date=date,
            read_throughput=message_read_throughput,
            write_throughput=message_write_throughput,
        )
    else:
        return Table(tablename)


def create_router_table(tablename="router", read_throughput=5,
                        write_throughput=5):
    # type: (str, int, int) -> Table
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


def _make_table(table_func, tablename, read_throughput, write_throughput):
    # type: (Callable[[str, int, int], Table], str, int, int) -> Table
    """Private common function to make a table with a table func"""
    if not table_exists(DynamoDBConnection(), tablename):
        return table_func(tablename, read_throughput, write_throughput)
    else:
        return Table(tablename)


def get_router_table(tablename="router", read_throughput=5,
                     write_throughput=5):
    # type: (str, int, int) -> Table
    """Get the main router table object

    Creates the table if it doesn't already exist, otherwise returns the
    existing table.

    """
    return _make_table(create_router_table, tablename, read_throughput,
                       write_throughput)


def preflight_check(message, router, uaid="deadbeef00000000deadbeef00000000"):
    # type: (Message, Router, str) -> None
    """Performs a pre-flight check of the router/message to ensure
    appropriate permissions for operation.

    Failure to run correctly will raise an exception.

    """
    # Verify tables are ready for use if they just got created
    ready = False
    while not ready:
        tbl_status = [x.describe()["Table"]["TableStatus"]
                      for x in [message.table, router.table]]
        ready = all([status == "ACTIVE" for status in tbl_status])
        if not ready:
            time.sleep(1)

    # Use a distinct UAID so it doesn't interfere with metrics
    uaid = uuid.UUID(uaid)
    chid = uuid.uuid4()
    message_id = str(uuid.uuid4())
    node_id = "mynode:2020"
    connected_at = 0
    notif = WebPushNotification(
        uaid=uaid,
        channel_id=chid,
        update_id=message_id,
        message_id=message_id,
        ttl=60,
    )

    # Store a notification, fetch it, delete it
    message.store_message(notif)
    assert message.delete_message(notif)

    # Store a router entry, fetch it, delete it
    router.register_user(dict(uaid=uaid.hex, node_id=node_id,
                              connected_at=connected_at,
                              router_type="webpush"))
    item = router.get_uaid(uaid.hex)
    assert item.get("node_id") == node_id
    # Clean up the preflight data.
    router.clear_node(item)
    router.drop_user(uaid.hex)


def track_provisioned(func):
    # type: (Callable[..., T]) -> Callable[..., T]
    """Tracks provisioned exceptions and increments a metric for them named
    after the function decorated"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if TRACK_DB_CALLS:
            DB_CALLS.append(func.__name__)
        return func(self, *args, **kwargs)
    return wrapper


def has_connected_this_month(item):
    # type: (ItemLike) -> bool
    """Whether or not a router item has connected this month"""
    last_connect = item.get("last_connect")
    if not last_connect:
        return False

    today = datetime.datetime.today()
    val = "%s%s" % (today.year, str(today.month).zfill(2))
    return str(last_connect).startswith(val)


def generate_last_connect():
    # type: () -> int
    """Generate a last_connect

    This intentionally generates a limited set of keys for each month in a
    known sequence. For each month, there's 24 hours * 10 random numbers for
    a total of 240 keys per month depending on when the user migrates forward.

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
    # type: (datetime.date) -> Iterable[int]
    """Generator of last_connect values for a given date

    Creates an iterator that yields all the valid values for ``last_connect``
    for a given year/month.

    """
    year = str(date.year)
    month = str(date.month).zfill(2)
    for hour in range(0, 24):
        for rand_int in range(0, 11):
            val = "".join([year, month, str(hour).zfill(2),
                           str(rand_int).zfill(4)])
            yield int(val)


def list_tables(conn):
    """Return a list of the names of all DynamoDB tables."""
    start_table = None
    while True:
        result = conn.list_tables(exclusive_start_table_name=start_table)
        for table in result.get('TableNames', []):
            yield table
        start_table = result.get('LastEvaluatedTableName', None)
        if not start_table:
            break


def table_exists(conn, tablename):
    """Determine if the specified Table exists"""
    return any(tablename == name for name in list_tables(conn))


class Message(object):
    """Create a Message table abstraction on top of a DynamoDB Table object"""
    def __init__(self, table, metrics):
        # type: (Table, IMetrics) -> None
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
        # type: (str, str) -> bool
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
        # type: (str, str, **str) -> bool
        """Remove a channel registration for a given uaid"""
        conn = self.table.connection
        db_key = self.encode({"uaid": hasher(uaid), "chidmessageid": " "})
        expr = "DELETE chids :channel_id"
        chid = normalize_id(channel_id)
        expr_values = self.encode({":channel_id": set([chid])})

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
                return chid in self.table._dynamizer.decode(chids)
            except (TypeError, AttributeError):  # pragma: nocover
                pass
        # if, for some reason, there are no chids defined, return False.
        return False

    @track_provisioned
    def all_channels(self, uaid):
        # type: (str) -> Tuple[bool, Set[str]]
        """Retrieve a list of all channels for a given uaid"""

        # Note: This only returns the chids associated with the UAID.
        # Functions that call store_message() would be required to
        # update that list as well using register_channel()
        try:
            result = self.table.get_item(consistent=True,
                                         uaid=hasher(uaid),
                                         chidmessageid=" ")
            return (True, result["chids"] or set([]))
        except ItemNotFound:
            return False, set([])

    @track_provisioned
    def save_channels(self, uaid, channels):
        # type: (str, Set[str]) -> None
        """Save out a set of channels"""
        self.table.put_item(data=dict(
            uaid=hasher(uaid),
            chidmessageid=" ",
            chids=channels
        ), overwrite=True)

    @track_provisioned
    def store_message(self, notification):
        # type: (WebPushNotification) -> None
        """Stores a WebPushNotification in the message table"""
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

    @track_provisioned
    def delete_message(self, notification):
        # type: (WebPushNotification) -> bool
        """Deletes a specific message"""
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
    def fetch_messages(
            self,
            uaid,  # type: uuid.UUID
            limit=10,  # type: int
            ):
        # type: (...) -> Tuple[Optional[int], List[WebPushNotification]]
        """Fetches messages for a uaid

        :returns: A tuple of the last timestamp to read for timestamped
                  messages and the list of non-timestamped messages.

        """
        # Eagerly fetches all results in the result set.
        results = list(self.table.query_2(uaid__eq=hasher(uaid.hex),
                                          chidmessageid__lt="02",
                                          consistent=True, limit=limit))

        # First extract the position if applicable, slightly higher than 01:
        # to ensure we don't load any 01 remainders that didn't get deleted
        # yet
        last_position = None
        if results:
            # Ensure we return an int, as boto2 can return Decimals
            if results[0].get("current_timestamp"):
                last_position = int(results[0]["current_timestamp"])

        return last_position, [
            WebPushNotification.from_message_table(uaid, x)
            for x in results[1:]
        ]

    @track_provisioned
    def fetch_timestamp_messages(
            self,
            uaid,  # type: uuid.UUID
            timestamp=None,  # type: Optional[int or str]
            limit=10,  # type: int
            ):
        # type: (...) -> Tuple[Optional[int], List[WebPushNotification]]
        """Fetches timestamped messages for a uaid

        Note that legacy messages start with a hex UUID, so they may be mixed
        in with timestamp messages beginning with 02. As such we only move our
        last_position forward to the last timestamped message.

        :returns: A tuple of the last timestamp to read and the list of
                  timestamped messages.

        """
        # Turn the timestamp into a proper sort key
        if timestamp:
            sortkey = "02:{timestamp}:z".format(timestamp=timestamp)
        else:
            sortkey = "01;"

        results = list(self.table.query_2(uaid__eq=hasher(uaid.hex),
                                          chidmessageid__gt=sortkey,
                                          consistent=True, limit=limit))
        notifs = [
            WebPushNotification.from_message_table(uaid, x) for x in results
        ]
        ts_notifs = [x for x in notifs if x.sortkey_timestamp]
        last_position = None
        if ts_notifs:
            last_position = ts_notifs[-1].sortkey_timestamp
        return last_position, notifs

    @track_provisioned
    def update_last_message_read(self, uaid, timestamp):
        # type: (uuid.UUID, int) -> bool
        """Update the last read timestamp for a user"""
        conn = self.table.connection
        db_key = self.encode({"uaid": hasher(uaid.hex), "chidmessageid": " "})
        expr = "SET current_timestamp=:timestamp"
        expr_values = self.encode({":timestamp": timestamp})
        conn.update_item(
            self.table.table_name,
            db_key,
            update_expression=expr,
            expression_attribute_values=expr_values,
        )
        return True


class Router(object):
    """Create a Router table abstraction on top of a DynamoDB Table object"""
    def __init__(self, table, metrics):
        # type: (Table, IMetrics) -> None
        """Create a new Router object

        :param table: :class:`Table` object.
        :param metrics: Metrics object that implements the
                        :class:`autopush.metrics.IMetrics` interface.

        """
        self.table = table
        self.metrics = metrics
        self.encode = table._encode_keys

    def get_uaid(self, uaid):
        # type: (str) -> Item
        """Get the database record for the UAID

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
            raise
        except JSONResponseError:  # pragma: nocover
            # We trap JSONResponseError because Moto returns text instead of
            # JSON when looking up values in empty tables. We re-throw the
            # correct ItemNotFound exception
            raise ItemNotFound("uaid not found")

    @track_provisioned
    def register_user(self, data):
        # type: (ItemLike) -> Tuple[bool, Dict[str, Any]]
        """Register this user

        If a record exists with a newer ``connected_at``, then the user will
        not be registered.

        :returns: Whether the user was registered or not.
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
            return (True, result)
        except ConditionalCheckFailedException:
            return (False, {})

    @track_provisioned
    def drop_user(self, uaid):
        # type: (str) -> bool
        """Drops a user record"""
        # The following hack ensures that only uaids that exist and are
        # deleted return true.
        huaid = hasher(uaid)
        return self.table.delete_item(uaid=huaid,
                                      expected={"uaid__eq": huaid})

    def delete_uaids(self, uaids):
        # type: (List[str]) -> None
        """Issue a batch delete call for the given uaids"""
        with self.table.batch_write() as batch:
            for uaid in uaids:
                batch.delete_item(uaid=uaid)

    def drop_old_users(self, months_ago=2):
        # type: (int) -> Iterable[int]
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

        :returns: Iterable of how many deletes were run

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
        # type: (str, str) -> bool
        """Update the route tables current_message_month

        Note that we also update the last_connect at this point since webpush
        users when connecting will always call this once that month. The
        current_timestamp is also reset as a new month has no last read
        timestamp.

        """
        conn = self.table.connection
        db_key = self.encode({"uaid": hasher(uaid)})
        expr = ("SET current_month=:curmonth, last_connect=:last_connect")
        expr_values = self.encode({":curmonth": month,
                                   ":last_connect": generate_last_connect(),
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
        # type: (Item) -> bool
        """Given a router item and remove the node_id

        The node_id will only be cleared if the ``connected_at`` matches up
        with the item's ``connected_at``.

        :returns: Whether the node was cleared or not.
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


@attrs
class DatabaseManager(object):
    """Provides database access"""

    _router_conf = attrib()   # type: DDBTableConfig
    _message_conf = attrib()  # type: DDBTableConfig

    metrics = attrib()  # type: IMetrics

    router = attrib(default=None)                   # type: Optional[Router]
    message_tables = attrib(default=Factory(dict))  # type: Dict[str, Message]
    current_msg_month = attrib(init=False)          # type: Optional[str]
    current_month = attrib(init=False)              # type: Optional[int]

    def __attrs_post_init__(self):
        """Initialize sane defaults"""
        today = datetime.date.today()
        self.current_month = today.month
        self.current_msg_month = make_rotating_tablename(
            self._message_conf.tablename,
            date=today
        )

    @classmethod
    def from_config(cls, conf, **kwargs):
        # type: (AutopushConfig, **Any) -> DatabaseManager
        """Create a DatabaseManager from the given config"""
        metrics = autopush.metrics.from_config(conf)
        return cls(
            router_conf=conf.router_table,
            message_conf=conf.message_table,
            metrics=metrics,
            **kwargs
        )

    def setup(self, preflight_uaid):
        # type: (str) -> None
        """Setup metrics, message tables and perform preflight_check"""
        self.metrics.start()
        self.setup_tables()
        preflight_check(self.message, self.router, preflight_uaid)

    def setup_tables(self):
        """Lookup or create the database tables"""
        self.router = Router(
            get_router_table(**asdict(self._router_conf)),
            self.metrics
        )
        # Used to determine whether a connection is out of date with current
        # db objects. There are three noteworty cases:
        # 1 "Last Month" the table requires a rollover.
        # 2 "This Month" the most common case.
        # 3 "Next Month" where the system will soon be rolling over, but with
        #   timing, some nodes may roll over sooner. Ensuring the next month's
        #   table is present before the switchover is the main reason for this,
        #   just in case some nodes do switch sooner.
        self.create_initial_message_tables()

    @property
    def message(self):
        # type: () -> Message
        """Property that access the current message table"""
        return self.message_tables[self.current_msg_month]

    @message.setter
    def message(self, value):
        # type: (Message) -> None
        """Setter to set the current message table"""
        self.message_tables[self.current_msg_month] = value

    def _tomorrow(self):
        # type: () -> datetime.date
        return datetime.date.today() + datetime.timedelta(days=1)

    def create_initial_message_tables(self):
        """Initializes a dict of the initial rotating messages tables.

        An entry for last months table, an entry for this months table,
        an entry for tomorrow, if tomorrow is a new month.

        """
        mconf = self._message_conf
        today = datetime.date.today()
        last_month = get_rotating_message_table(
            prefix=mconf.tablename,
            delta=-1,
            message_read_throughput=mconf.read_throughput,
            message_write_throughput=mconf.write_throughput
        )
        this_month = get_rotating_message_table(
            prefix=mconf.tablename,
            message_read_throughput=mconf.read_throughput,
            message_write_throughput=mconf.write_throughput
        )
        self.current_month = today.month
        self.current_msg_month = this_month.table_name
        self.message_tables = {
            last_month.table_name: Message(last_month, self.metrics),
            this_month.table_name: Message(this_month, self.metrics)
        }
        if self._tomorrow().month != today.month:
            next_month = get_rotating_message_table(
                prefix=mconf.tablename,
                delta=1,
                message_read_throughput=mconf.read_throughput,
                message_write_throughput=mconf.write_throughput
            )
            self.message_tables[next_month.table_name] = Message(
                next_month, self.metrics)

    @inlineCallbacks
    def update_rotating_tables(self):
        # type: () -> Generator
        """This method is intended to be tasked to run periodically off the
        twisted event hub to rotate tables.

        When today is a new month from yesterday, then we swap out all the
        table objects on the settings object.

        """
        mconf = self._message_conf
        today = datetime.date.today()
        tomorrow = self._tomorrow()
        if ((tomorrow.month != today.month) and
                sorted(self.message_tables.keys())[-1] != tomorrow.month):
            next_month = yield deferToThread(
                get_rotating_message_table,
                prefix=mconf.tablename,
                delta=0,
                date=tomorrow,
                message_read_throughput=mconf.read_throughput,
                message_write_throughput=mconf.write_throughput
            )
            self.message_tables[next_month.table_name] = Message(
                next_month, self.metrics)

        if today.month == self.current_month:
            # No change in month, we're fine.
            returnValue(False)

        # Get tables for the new month, and verify they exist before we try to
        # switch over
        message_table = yield deferToThread(
            get_rotating_message_table,
            prefix=mconf.tablename,
            message_read_throughput=mconf.read_throughput,
            message_write_throughput=mconf.write_throughput
        )

        # Both tables found, safe to switch-over
        self.current_month = today.month
        self.current_msg_month = message_table.table_name
        self.message_tables[self.current_msg_month] = Message(
            message_table, self.metrics)
        returnValue(True)
