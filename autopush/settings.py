"""Autopush Settings Object and Setup"""
import datetime
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
from twisted.web.client import Agent, HTTPConnectionPool, _HTTP11ClientFactory

from autopush.db import (
    get_router_table,
    get_storage_table,
    get_rotating_message_table,
    preflight_check,
    Storage,
    Router,
    Message,
)
from autopush.exceptions import InvalidTokenException, VapidAuthException
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
from autopush.utils import (
    canonical_url,
    resolve_ip,
    repad,
    base64url_decode
)
from autopush.crypto_key import (CryptoKey, CryptoKeyException)


class QuietClientFactory(_HTTP11ClientFactory):
    """Silence the start/stop factory messages."""
    noisy = False


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
                 router_conf=None,
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
                 hello_timeout=0,
                 bear_hash_key=None,
                 preflight_uaid="deadbeef00000000deadbeef00000000",
                 ami_id=None,
                 client_certs=None,
                 msg_limit=100,
                 debug=False,
                 ):
        """Initialize the Settings object

        Upon creation, the HTTP agent will initialize, all configured routers
        will be setup and started, logging will be started, and the database
        will have a preflight check done.

        """
        # Use a persistent connection pool for HTTP requests.
        pool = HTTPConnectionPool(reactor)
        if not debug:
            pool._factory = QuietClientFactory

        self.agent = Agent(reactor, connectTimeout=5, pool=pool)

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

        # Metrics setup
        if datadog_api_key:
            self.metrics = DatadogMetrics(
                hostname=self.hostname,
                api_key=datadog_api_key,
                app_key=datadog_app_key,
                flush_interval=datadog_flush_interval,
            )
        elif statsd_host:
            self.metrics = TwistedMetrics(statsd_host, statsd_port)
        else:
            self.metrics = SinkMetrics()

        self.port = port
        self.endpoint_hostname = endpoint_hostname or self.hostname
        self.router_hostname = router_hostname or self.hostname

        if router_conf is None:
            router_conf = {}
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
        self.enable_tls_auth = client_certs is not None
        self.client_certs = client_certs

        # Database objects
        self.router_table = get_router_table(router_tablename,
                                             router_read_throughput,
                                             router_write_throughput)
        self.storage_table = get_storage_table(
            storage_tablename,
            storage_read_throughput,
            storage_write_throughput)
        self.message_table = get_rotating_message_table(
            message_tablename,
            message_read_throughput=message_read_throughput,
            message_write_throughput=message_write_throughput)
        self._message_prefix = message_tablename
        self.message_limit = msg_limit
        self.storage = Storage(self.storage_table, self.metrics)
        self.router = Router(self.router_table, self.metrics)

        # Used to determine whether a connection is out of date with current
        # db objects. There are three noteworty cases:
        # 1 "Last Month" the table requires a rollover.
        # 2 "This Month" the most common case.
        # 3 "Next Month" where the system will soon be rolling over, but with
        #   timing, some nodes may roll over sooner. Ensuring the next month's
        #   table is present before the switchover is the main reason for this,
        #   just in case some nodes do switch sooner.
        self.create_initial_message_tables()

        # Run preflight check
        preflight_check(self.storage, self.router, preflight_uaid)

        # CORS
        self.cors = enable_cors

        # Force timeout in idle seconds
        self.wake_timeout = wake_timeout

        # Setup the routers
        self.routers = dict()
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

        self.ami_id = ami_id

        # Generate messages per legacy rules, only used for testing to
        # generate legacy data.
        self._notification_legacy = False

    @property
    def message(self):
        """Property that access the current message table"""
        return self.message_tables[self.current_msg_month]

    @message.setter
    def message(self, value):
        """Setter to set the current message table"""
        self.message_tables[self.current_msg_month] = value

    def _tomorrow(self):
        return datetime.date.today() + datetime.timedelta(days=1)

    def create_initial_message_tables(self):
        """Initializes a dict of the initial rotating messages tables.

        An entry for last months table, an entry for this months table,
        an entry for tomorrow, if tomorrow is a new month.

        """
        today = datetime.date.today()
        last_month = get_rotating_message_table(self._message_prefix, -1)
        this_month = get_rotating_message_table(self._message_prefix)
        self.current_month = today.month
        self.current_msg_month = this_month.table_name
        self.message_tables = {
            last_month.table_name: Message(last_month, self.metrics),
            this_month.table_name: Message(this_month, self.metrics)
        }
        if self._tomorrow().month != today.month:
            next_month = get_rotating_message_table(self._message_prefix,
                                                    delta=1)
            self.message_tables[next_month.table_name] = Message(
                next_month, self.metrics)

    @inlineCallbacks
    def update_rotating_tables(self):
        """This method is intended to be tasked to run periodically off the
        twisted event hub to rotate tables.

        When today is a new month from yesterday, then we swap out all the
        table objects on the settings object.

        """
        today = datetime.date.today()
        tomorrow = self._tomorrow()
        if ((tomorrow.month != today.month) and
                sorted(self.message_tables.keys())[-1] !=
                tomorrow.month):
            next_month = yield deferToThread(
                get_rotating_message_table,
                self._message_prefix, 0, tomorrow
            )
            self.message_tables[next_month.table_name] = Message(
                next_month, self.metrics)

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

    def make_simplepush_endpoint(self, uaid, chid):
        """Create a simplepush endpoint"""
        root = self.endpoint_url + "/spush/"
        base = (uaid.replace('-', '').decode("hex") +
                chid.replace('-', '').decode("hex"))
        return root + 'v1/' + self.fernet.encrypt(base).strip('=')

    def make_endpoint(self, uaid, chid, key=None):
        """Create an v1 or v2 WebPush endpoint from the identifiers.

        Both endpoints use bytes instead of hex to reduce ID length.
        v1 is the uaid + chid
        v2 is the uaid + chid + sha256(key).bytes

        :param uaid: User Agent Identifier
        :param chid: Channel or Subscription ID
        :param key: Optional Base64 URL-encoded application server key
        :returns: Push endpoint

        """
        root = self.endpoint_url + '/wpush/'
        base = (uaid.replace('-', '').decode("hex") +
                chid.replace('-', '').decode("hex"))

        if key is None:
            return root + 'v1/' + self.fernet.encrypt(base).strip('=')

        raw_key = base64url_decode(key.encode('utf8'))
        ep = self.fernet.encrypt(base + sha256(raw_key).digest()).strip('=')
        return root + 'v2/' + ep

    def parse_endpoint(self, token, version="v1", ckey_header=None,
                       auth_header=None):
        """Parse an endpoint into component elements of UAID, CHID and optional
        key hash if v2

        :param token: The obscured subscription data.
        :param version: This is the API version of the token.
        :param ckey_header: the Crypto-Key header bearing the public key
        (from Crypto-Key: p256ecdsa=)
        :param auth_header: The Authorization header bearing the VAPID info

        :raises ValueError: In the case of a malformed endpoint.

        :returns: a dict containing (uaid=UAID, chid=CHID, public_key=KEY)

        """
        token = self.fernet.decrypt(repad(token).encode('utf8'))
        public_key = None
        if ckey_header:
            try:
                crypto_key = CryptoKey(ckey_header)
            except CryptoKeyException:
                raise InvalidTokenException("Invalid key data")
            public_key = crypto_key.get_label('p256ecdsa')

        if version == 'v1' and len(token) != 32:
            raise InvalidTokenException("Corrupted push token")
        if version == 'v2':
            if not auth_header:
                raise VapidAuthException("Missing Authorization Header")
            if len(token) != 64:
                raise InvalidTokenException("Corrupted push token")
            if not public_key:
                raise VapidAuthException("Invalid key data")
            try:
                decoded_key = base64url_decode(public_key)
            except TypeError:
                raise VapidAuthException("Invalid key data")
            if not constant_time.bytes_eq(sha256(decoded_key).digest(),
                                          token[32:]):
                raise VapidAuthException("Key mismatch")
        return dict(uaid=token[:16].encode('hex'),
                    chid=token[16:32].encode('hex'),
                    version=version,
                    public_key=public_key)
