"""A small collection of Autopush utility functions"""
import base64
import hashlib
import hmac
import socket
import uuid

import ecdsa
from jose import jws

from twisted.python import failure, log


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


def parse_header(header, major=";", minor="="):
    """Convert a multi-component header line (e.g. "a;b=c;d=e;...") to
    a list.

    For example, if the header content line is

    `"a;c=1;b;d=2+3=5"`

    and presuming default values for major and minor, then the
    response would be:

    `['a', 'b', {'c': '1', 'd': '2+3=5'}]`

    items defined with values will always appear as a dictionary at the
    end of the list. If no items are assigned values, then no dictionary
    is appended.

    :param header: Header content line to parse.
    :param major: Major item separator.
    :param minor: Minor item separator.

    """
    vals = dict()
    items = []
    if not header:
        return items
    for v in map(lambda x: x.strip().split(minor, 1),
                 header.split(major)):
        try:
            val = v[1]
            # Trim quotes equally off of start and end
            # because ""this is "quoted""" is a thing.
            while val[0] == val[-1] == '"':
                val = val[1:-1]
            vals[v[0].lower()] = val
        except IndexError:
            if len(v[0]):
                items.append(v[0].strip('"'))
    if vals:
        items.append(vals)
    return items


def fix_padding(string):
    """ Some JWT fields may strip the end padding from base64 strings """
    if len(string) % 4:
        return string + '===='[len(string) % 4:]
    return string


def extract_jwt(token, crypto_key):
    """ Extract the claims from the validated JWT. """
    # first split and convert the jwt.
    if not token or not crypto_key:
        return {}

    key = base64.urlsafe_b64decode(fix_padding(crypto_key))
    vk = ecdsa.VerifyingKey.from_string(key, curve=ecdsa.NIST256p)
    return jws.verify(token, vk, algorithms=["ES256"])


class ErrorLogger (object):

    def write_error(self, code, **kwargs):
        """Write the error (otherwise unhandled exception when dealing with
        unknown method specifications.)

        This is a Cyclone API Override method used by endpoint and websocket.

        """
        self.set_status(code)
        if "exc_info" in kwargs:
            log.err(failure.Failure(*kwargs["exc_info"]),
                    **self._client_info)
        else:
            log.err("Error in handler: %s" % code, **self._client_info)
        self.finish()
