"""A small collection of Autopush utility functions"""
import base64
import hashlib
import hmac
import socket
import uuid

import ecdsa
from jose import jws

from twisted.logger import Logger
from twisted.python import failure


default_ports = {
    "ws": 80,
    "http": 80,
    "wss": 443,
    "https": 443,
}


def canonical_url(scheme, hostname, port=None):
    """Return a canonical URL given a scheme/hostname and optional port"""
    if port is None or port == default_ports.get(scheme):
        return "%s://%s" % (scheme, hostname)
    return "%s://%s:%s" % (scheme, hostname, port)


def resolve_ip(hostname):
    """Resolve a hostname to its IP if possible"""
    interfaces = socket.getaddrinfo(hostname, 0, socket.AF_INET,
                                    socket.SOCK_STREAM,
                                    socket.IPPROTO_TCP)
    if len(interfaces) == 0:
        return hostname
    addr = interfaces[0][-1]
    return addr[0]


def validate_uaid(uaid):
    """Validates a UAID a tuple indicating if its valid and the original
    uaid, or a new uaid if its invalid"""
    if uaid:
        try:
            return bool(uuid.UUID(uaid)), uaid
        except ValueError:
            pass
    return False, uuid.uuid4().hex


def generate_hash(key, payload):
    """Generate a HMAC for the uaid using the secret

    :returns: HMAC hash and the nonce used as a tuple (nonce, hash).

    """
    h = hmac.new(key=key, msg=payload, digestmod=hashlib.sha256)
    return h.hexdigest()


def base64url_encode(string):
    """Encodes an unpadded Base64 URL-encoded string per RFC 7515."""
    return base64.urlsafe_b64encode(string).strip('=')


def repad(string):
    """Adds padding to strings for base64 decoding"""

    if len(string) % 4:
        string = string + '===='[len(string) % 4:]
    return string


def base64url_decode(string):
    """Decodes a Base64 URL-encoded string per RFC 7515.

    RFC 7515 (used for Encrypted Content-Encoding and JWT) requires unpadded
    encoded strings, but Python's ``urlsafe_b64decode`` only accepts padded
    strings.
    """
    return base64.urlsafe_b64decode(repad(string))


def decipher_public_key(key_data):
    """A public key may come in several flavors. Attempt to extract the
    valid key bits from keys doing minimal validation checks.

    This is mostly a result of libs like WebCrypto prefixing data to "raw"
    keys, and the ecdsa library not really providing helpful errors.

    :param key_data: the raw-ish key we're going to try and process
    :returns: the raw key data.
    :raises: ValueError for unknown or poorly formatted keys.

    """
    # key data is actually a raw coordinate pair
    key_len = len(key_data)
    if key_len == 64:
        return key_data
    # Key format is "raw"
    if key_len == 65 and key_data[0] == '\x04':
        return key_data[-64:]
    # key format is "spki"
    if key_len == 88 and key_data[:3] == '0V0':
        return key_data[-64:]
    raise ValueError("Unknown public key format specified")


def extract_jwt(token, crypto_key):
    """Extract the claims from the validated JWT. """
    # first split and convert the jwt.
    if not token or not crypto_key:
        return {}

    key = decipher_public_key(crypto_key)
    vk = ecdsa.VerifyingKey.from_string(key, curve=ecdsa.NIST256p)
    return jws.verify(token, vk, algorithms=["ES256"])


class ErrorLogger(object):
    log = Logger()

    def write_error(self, code, **kwargs):
        """Write the error (otherwise unhandled exception when dealing with
        unknown method specifications.)

        This is a Cyclone API Override method used by endpoint and websocket.

        """
        self.set_status(code)
        if "exc_info" in kwargs:
            fmt = kwargs.get("format", "Exception")
            self.log.failure(
                format=fmt,
                failure=failure.Failure(*kwargs["exc_info"]),
                **self._client_info)
        else:
            self.log.failure("Error in handler: %s" % code,
                             **self._client_info)
        self.finish()
