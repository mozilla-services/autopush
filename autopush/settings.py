"""Autopush Settings Object and Setup"""
import datetime
import re
import socket

from hashlib import sha256

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import constant_time
from twisted.internet import reactor
from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
)
from twisted.internet.threads import deferToThread
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
from autopush.exceptions import InvalidTokenException
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
from autopush.crypto_key import (CryptoKey, CryptoKeyException)


VALID_V0_TOKEN = re.compile(r'[0-9A-Za-z-]{32,36}:[0-9A-Za-z-]{32,36}')


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
                 bear_hash_key=None,
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

        if bear_hash_key is None:
            bear_hash_key = []
        if not isinstance(bear_hash_key, list):
            bear_hash_key = [bear_hash_key]
        self.bear_hash_key = bear_hash_key

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
        message_table = yield deferToThread(get_rotating_message_table,
                                            self._message_prefix)

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

    def make_endpoint(self, uaid, chid, key=None):
        """Create an v1 or v2 endpoint from the indentifiers.

        Both endpoints use bytes instead of hex to reduce ID length.
        v0 is uaid.hex + ':' + chid.hex and is deprecated.
        v1 is the uaid + chid
        v2 is the uaid + chid + sha256(key).bytes

        :param uaid: User Agent Identifier
        :param chid: Channel or Subscription ID
        :param key: Optional provided Public Key
        :returns: Push endpoint

        """
        root = self.endpoint_url + '/push/'
        base = (uaid.replace('-', '').decode("hex") +
                chid.replace('-', '').decode("hex"))

        if key is None:
            return root + 'v1/' + self.fernet.encrypt(base).strip('=')

        return root + 'v2/' + self.fernet.encrypt(base + sha256(key).digest())

    def parse_endpoint(self, token, version="v0", ckey_header=None):
        """Parse an endpoint into component elements of UAID, CHID and optional
        key hash if v2

        :param token: The obscured subscription data.
        :param version: This is the API version of the token.
        :param ckey_header: the Crypto-Key header bearing the public key
        (from Crypto-Key: p256ecdsa=)

        :raises ValueError: In the case of a malformed endpoint.

        :returns: a dict containing (uaid=UAID, chid=CHID, public_key=KEY)

        """

        token = self.fernet.decrypt(token.encode('utf8'))
        public_key = None
        if ckey_header:
            try:
                public_key = CryptoKey(ckey_header).get_label('p256ecdsa')
            except CryptoKeyException:
                raise InvalidTokenException("Invalid key data")

        if version == 'v0':
            if not VALID_V0_TOKEN.match(token):
                raise InvalidTokenException("Corrupted push token")
            items = token.split(':')
            return dict(uaid=items[0], chid=items[1], public_key=public_key)
        if version == 'v1' and len(token) != 32:
            raise InvalidTokenException("Corrupted push token")
        if version == 'v2':
            if len(token) != 64:
                raise InvalidTokenException("Corrupted push token")
            if not public_key:
                raise InvalidTokenException("Invalid key data")
            if not constant_time.bytes_eq(sha256(public_key).digest(),
                                          token[32:]):
                raise InvalidTokenException("Key mismatch")
        return dict(uaid=token[:16].encode('hex'),
                    chid=token[16:32].encode('hex'),
                    public_key=public_key)
