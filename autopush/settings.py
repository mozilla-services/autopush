import socket

import requests
from cryptography.fernet import Fernet

from autopush.db import (
    get_router_table,
    get_storage_table,
    Storage,
    Router
)


class AutopushSettings(object):
    options = ["crypto_key", "hostname", "min_ping_interval",
               "max_data"]

    def __init__(self):
        sess = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=100,
                                                pool_maxsize=100)
        sec_adapter = requests.adapters.HTTPAdapter(pool_connections=100,
                                                    pool_maxsize=100)
        sess.mount('http://', adapter)
        sess.mount('https://', sec_adapter)
        self.requests = sess
        key = Fernet.generate_key()
        self.fernet = Fernet(key)
        self.hostname = socket.gethostname()
        self.min_ping_interval = 20
        self.max_data = 4096
        self.clients = {}
        self.router_table = get_router_table()
        self.storage_table = get_storage_table()
        self.storage = Storage(self.storage_table)
        self.router = Router(self.router_table)

    def update(self, **kwargs):
        for key, val in kwargs.items():
            if key == "crypto_key":
                self.fernet = Fernet(val)
            else:
                setattr(self, key, val)
