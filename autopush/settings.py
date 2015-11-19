"""Autopush Settings Object and Setup"""
import datetime
import socket

from cryptography.fernet import Fernet, MultiFernet
from twisted.internet import reactor
from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
)
from twisted.internet.threads import deferToThread
from twisted.python import log
from twisted.web.client import Agent, HTTPConnectionPool

from autopush.db import (
    get_router_table,
    get_storage_table,
    get_rotating_message_table,
    make_rotating_tablename,
    preflight_check,
    Storage,
    Router,
    Message
)
from autopush.metrics import (
    DatadogMetrics,
    TwistedMetrics,
    SinkMetrics,
)
from autopush.router import (
    APNSRouter,
    GCMRouter,
    SimpleRouter,
    WebPushRouter,
)
from autopush.utils import canonical_url, resolve_ip
from autopush.senderids import SENDERID_EXPRY, DEFAULT_BUCKET


class AutopushSettings(object):
    """Main Autopush Settings Object"""
    options = ["crypto_key", "hostname", "min_ping_interval",
               "max_data"]

    def __init__(self,
                 crypto_key=None,
                 datadog_api_key=None,
                 datadog_app_key=None,
                 datadog_flush_interval=None,
                 hostname=None,
                 port=None,
                 router_scheme=None,
                 router_hostname=None,
                 router_port=None,
                 endpoint_scheme=None,
                 endpoint_hostname=None,
                 endpoint_port=None,
                 router_conf={},
                 router_tablename="router",
                 router_read_throughput=5,
                 router_write_throughput=5,
                 storage_tablename="storage",
                 storage_read_throughput=5,
                 storage_write_throughput=5,
                 message_tablename="message",
                 message_read_throughput=5,
                 message_write_throughput=5,
                 statsd_host="localhost",
                 statsd_port=8125,
                 resolve_hostname=False,
                 max_data=4096,
                 # Reflected up from UDP Router
                 wake_timeout=0,
                 env='development',
                 enable_cors=False,
                 s3_bucket=DEFAULT_BUCKET,
                 senderid_expry=SENDERID_EXPRY,
                 senderid_list={},
                 hello_timeout=0,
                 ):
        """Initialize the Settings object

        Upon creation, the HTTP agent will initialize, all configured routers
        will be setup and started, logging will be started, and the database
        will have a preflight check done.

        """
        # Use a persistent connection pool for HTTP requests.
        pool = HTTPConnectionPool(reactor)
        self.agent = Agent(reactor, connectTimeout=5, pool=pool)

        # Metrics setup
        if datadog_api_key:
            self.metrics = DatadogMetrics(
                api_key=datadog_api_key,
                app_key=datadog_app_key,
                flush_interval=datadog_flush_interval
            )
        elif statsd_host:
            self.metrics = TwistedMetrics(statsd_host, statsd_port)
        else:
            self.metrics = SinkMetrics()
        if not crypto_key:
            crypto_key = [Fernet.generate_key()]
        if not isinstance(crypto_key, list):
            crypto_key = [crypto_key]
        self.update(crypto_key=crypto_key)
        self.crypto_key = crypto_key

        self.max_data = max_data
        self.clients = {}

        # Setup hosts/ports/urls
        default_hostname = socket.gethostname()
        self.hostname = hostname or default_hostname
        if resolve_hostname:
            self.hostname = resolve_ip(self.hostname)

        self.port = port
        self.endpoint_hostname = endpoint_hostname or self.hostname
        self.router_hostname = router_hostname or self.hostname

        self.router_conf = router_conf
        self.router_url = canonical_url(
            router_scheme or 'http',
            self.router_hostname,
            router_port
        )

        self.endpoint_url = canonical_url(
            endpoint_scheme or 'http',
            self.endpoint_hostname,
            endpoint_port
        )

        # Database objects
        self.router_table = get_router_table(router_tablename,
                                             router_read_throughput,
                                             router_write_throughput)
        self.storage_table = get_storage_table(
            storage_tablename,
            storage_read_throughput,
            storage_write_throughput)
        self.message_table = get_rotating_message_table(
            message_tablename)
        self._message_prefix = message_tablename
        self.storage = Storage(self.storage_table, self.metrics)
        self.router = Router(self.router_table, self.metrics)

        # Used to determine whether a connection is out of date with current
        # db objects
        self.current_msg_month = make_rotating_tablename(self._message_prefix)
        self.current_month = datetime.date.today().month
        self.create_initial_message_tables()

        # Run preflight check
        preflight_check(self.storage, self.router)

        # CORS
        self.cors = enable_cors

        # Force timeout in idle seconds
        self.wake_timeout = wake_timeout

        # Setup the routers
        self.routers = {}
        self.routers["simplepush"] = SimpleRouter(
            self,
            router_conf.get("simplepush")
        )
        self.routers["webpush"] = WebPushRouter(self, None)
        if 'apns' in router_conf:
            self.routers["apns"] = APNSRouter(self, router_conf["apns"])
        if 'gcm' in router_conf:
            self.routers["gcm"] = GCMRouter(self, router_conf["gcm"])

        # Env
        self.env = env

        self.hello_timeout = hello_timeout

    @property
    def message(self):
        """Property that access the current message table"""
        return self.message_tables[self.current_msg_month]

    @message.setter
    def message(self, value):
        """Setter to set the current message table"""
        self.message_tables[self.current_msg_month] = value

    def create_initial_message_tables(self):
        """Initializes a dict of the initial rotating messages tables.

        An entry for last months table, and an entry for this months table.

        """
        last_month = get_rotating_message_table(self._message_prefix, -1)
        this_month = get_rotating_message_table(self._message_prefix)
        self.message_tables = {
            last_month.table_name: Message(last_month, self.metrics),
            this_month.table_name: Message(this_month, self.metrics),
        }

    @inlineCallbacks
    def update_rotating_tables(self):
        """This method is intended to be tasked to run periodically off the
        twisted event hub to rotate tables.

        When today is a new month from yesterday, then we swap out all the
        table objects on the settings object.

        """
        today = datetime.date.today()
        if today.month == self.current_month:
            # No change in month, we're fine.
            returnValue(False)

        # Get tables for the new month, and verify they exist before we try to
        # switch over
        message_table = get_rotating_message_table(self._message_prefix)

        try:
            yield deferToThread(message_table.describe)
        except Exception:
            tblname = make_rotating_tablename(self._message_prefix)
            log.err("Unable to locate new message table: %s" % tblname)
            returnValue(False)

        # Both tables found, safe to switch-over
        self.current_month = today.month
        self.current_msg_month = message_table.table_name
        self.message_tables[self.current_msg_month] = \
            Message(message_table, self.metrics)
        returnValue(True)

    def update(self, **kwargs):
        """Update the arguments, if a ``crypto_key`` is in kwargs then the
        ``self.fernet`` attribute will be initialized"""
        for key, val in kwargs.items():
            if key == "crypto_key":
                fkeys = []
                if not isinstance(val, list):
                    val = [val]
                for v in val:
                    fkeys.append(Fernet(v))
                self.fernet = MultiFernet(fkeys)
            else:
                setattr(self, key, val)

    def make_endpoint(self, uaid, chid):
        """ Create an endpoint from the identifiers"""
        return self.endpoint_url + '/push/' + \
            self.fernet.encrypt((uaid + ':' + chid).encode('utf8'))
