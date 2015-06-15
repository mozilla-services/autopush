import socket

from cryptography.fernet import Fernet
from twisted.internet import reactor
from twisted.web.client import Agent, HTTPConnectionPool

from autopush.db import (
    get_router_table,
    get_storage_table,
    preflight_check,
    Storage,
    Router
)
from autopush.metrics import DatadogMetrics, TwistedMetrics
from autopush.utils import canonical_url, resolve_ip

from autopush.bridge.bridge import Bridge


class MetricSink(object):
    """Exists to swallow metrics when metrics are not active"""
    def increment(*args, **kwargs):
        pass


class AutopushSettings(object):
    options = ["crypto_key", "hostname", "min_ping_interval",
               "max_data"]

    def __init__(self,
                 crypto_key=None,
                 datadog_api_key=None,
                 datadog_app_key=None,
                 datadog_flush_interval=None,
                 hostname=None,
                 port=None,
                 db_host=None,
                 db_port=None,
                 db_secure=None,
                 router_scheme=None,
                 router_hostname=None,
                 router_port=None,
                 endpoint_scheme=None,
                 endpoint_hostname=None,
                 endpoint_port=None,
                 router_tablename="router",
                 router_read_throughput=5,
                 router_write_throughput=5,
                 storage_tablename="storage",
                 storage_read_throughput=5,
                 storage_write_throughput=5,
                 statsd_host="localhost",
                 statsd_port=8125,
                 pingConf=None,
                 resolve_hostname=False,
                 max_data=4096,
                 enable_cors=False):

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
            self.metrics = MetricSink()

        key = crypto_key or Fernet.generate_key()
        self.fernet = Fernet(key)

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
                                             router_write_throughput,
                                             db_host, db_port, db_secure)
        self.storage_table = get_storage_table(storage_tablename,
                                               storage_read_throughput,
                                               storage_write_throughput,
                                               db_host, db_port, db_secure)
        self.storage = Storage(self.storage_table, self.metrics)
        self.router = Router(self.router_table, self.metrics)

        # Run preflight check
        preflight_check(self.storage, self.router)

        self.bridge = None
        if pingConf is not None:
            self.bridge = Bridge(self.storage, pingConf)

        # CORS
        self.cors = enable_cors

    def update(self, **kwargs):
        for key, val in kwargs.items():
            if key == "crypto_key":
                self.fernet = Fernet(val)
            else:
                setattr(self, key, val)

    def makeEndpoint(self, uaid, chid):
        """ Create an endpoint from the identifiers"""
        return self.endpoint_url + '/push/' + \
            self.fernet.encrypt((uaid + ':' + chid).encode('utf8'))
