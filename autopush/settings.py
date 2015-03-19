import socket

import requests
from cryptography.fernet import Fernet
from txstatsd.client import TwistedStatsDClient
from txstatsd.metrics.metrics import Metrics

from autopush.db import (
    get_router_table,
    get_storage_table,
    Storage,
    Router
)

from autopush.pinger.pinger import Pinger


class AutopushSettings(object):
    options = ["crypto_key", "hostname", "min_ping_interval",
               "max_data"]

    def __init__(self,
                 crypto_key=None,
                 hostname=None,
                 port=None,
                 router_hostname=None,
                 router_port=None,
                 endpoint_hostname=None,
                 endpoint_port=None,
                 statsd_host="localhost",
                 statsd_port=8125,
                 pingConf=None):

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
        if statsd_host:
            client = TwistedStatsDClient(statsd_host, statsd_port)
            self.metrics_client = client
            self.metrics = Metrics(connection=client, namespace="pushgo")

        key = crypto_key or Fernet.generate_key()
        self.fernet = Fernet(key)

        self.min_ping_interval = 20
        self.max_data = 4096
        self.clients = {}

        # Setup hosts/ports/urls
        default_hostname = socket.gethostname()
        self.hostname = hostname or default_hostname
        self.port = port
        self.endpoint_hostname = endpoint_hostname or default_hostname
        self.endpoint_port = endpoint_port
        self.router_hostname = router_hostname or default_hostname
        self.router_port = router_port

        if endpoint_port == 80:
            self.endpoint_url = "http://" + self.endpoint_hostname
        elif endpoint_port == 443:
            self.endpoint_url = "https://" + self.endpoint_hostname
        else:
            self.endpoint_url = "http://%s:%s" % (self.endpoint_hostname,
                                                  endpoint_port)

        # Database objects
        self.router_table = get_router_table()
        self.storage_table = get_storage_table()
        self.storage = Storage(self.storage_table)
        self.router = Router(self.router_table)
        if pingConf is not None:
            self.pinger = Pinger(self.storage, pingConf)

    def update(self, **kwargs):
        for key, val in kwargs.items():
            if key == "crypto_key":
                self.fernet = Fernet(val)
            else:
                setattr(self, key, val)
