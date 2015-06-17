"""A small collection of Autopush utility functions"""
import hashlib
import hmac
import socket
import uuid


default_ports = {
    "ws": 80,
    "http": 80,
    "wss": 443,
    "https": 443,
}


def str2bool(v):
    """Convert different string representations of true/false into a Python
    bool"""
    return v in ("1", "t", "T", "true", "TRUE", "True")


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
    return False, str(uuid.uuid4())


def validate_hash(key, payload, hashed):
    """Validates that a UAID matches the HMAC value using the supplied
    secret"""
    h = hmac.new(key=key, msg=payload, digestmod=hashlib.sha256)
    return hmac.compare_digest(hashed, h.hexdigest())


def generate_hash(key, payload):
    """Generate a HMAC for the uaid using the secret

    :returns: HMAC hash and the nonce used as a tuple (nonce, hash).

    """
    h = hmac.new(key=key, msg=payload, digestmod=hashlib.sha256)
    return h.hexdigest()
