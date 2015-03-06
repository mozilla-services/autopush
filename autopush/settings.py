import socket
from cryptography.fernet import Fernet


class AutopushSettings(object):
    options = ["crypto_key", "hostname", "min_ping_interval",
               "max_data"]

    def __init__(self):
        key = Fernet.generate_key()
        self.fernet = Fernet(key)
        self.hostname = socket.gethostname()
        self.min_ping_interval = 20
        self.max_data = 4096

    def update(self, **kwargs):
        for key, val in kwargs:
            if key == "crypto_key":
                self.fernet = Fernet(val)
            else:
                setattr(self, key, val)
