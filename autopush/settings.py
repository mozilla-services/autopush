"""Autopush Settings Object and Setup"""
import socket

from cryptography.fernet import Fernet, MultiFernet
from twisted.internet import reactor
from twisted.web.client import Agent, HTTPConnectionPool

from autopush.db import (
    get_router_table,
    get_storage_table,
    get_message_table,
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
                 auth_key=None,
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

        if not auth_key:
            auth_key = crypto_key
        if not isinstance(auth_key, list):
            auth_key = [auth_key]
        self.auth_key = auth_key

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
        self.storage_table = get_storage_table(storage_tablename,
                                               storage_read_throughput,
                                               storage_write_throughput)
        self.message_table = get_message_table(message_tablename,
                                               message_read_throughput,
                                               message_write_throughput)
        self.storage = Storage(self.storage_table, self.metrics)
        self.router = Router(self.router_table, self.metrics)
        self.message = Message(self.message_table, self.metrics)

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
