import socket

import requests
from cryptography.fernet import Fernet

from autopush.db import (
    get_router_table,
    get_storage_table,
    Storage,
    Router
)
from autopush.metrics import DatadogMetrics, TwistedMetrics

from autopush.pinger.pinger import Pinger


default_ports = {
    "ws": 80,
    "http": 80,
    "wss": 443,
    "https": 443,
}

def canonical_url(scheme, hostname, port=None):
    if port is None or port == default_ports.get(scheme):
        return "%s://%s" % (scheme, hostname)
    return "%s://%s:%s" % (scheme, hostname, port)


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
                 enable_cors=False):

        # Setup the requests lib session
        sess = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=100,
                                                pool_maxsize=100)
        sec_adapter = requests.adapters.HTTPAdapter(pool_connections=100,
                                                    pool_maxsize=100)
        sess.mount('http://', adapter)
        sess.mount('https://', sec_adapter)
        self.requests = sess

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

        self.min_ping_interval = 20
        self.max_data = 4096
        self.clients = {}

        # Setup hosts/ports/urls
        default_hostname = socket.gethostname()
        self.hostname = hostname or default_hostname
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
                                             router_write_throughput)
        self.storage_table = get_storage_table(storage_tablename,
                                               storage_read_throughput,
                                               storage_write_throughput)
        self.storage = Storage(self.storage_table, self.metrics)
        self.router = Router(self.router_table, self.metrics)
        self.pinger = None
        if pingConf is not None:
            self.pinger = Pinger(self.storage, pingConf)

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
