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
    return v in ("1", "t", "T", "true", "TRUE", "True")


def canonical_url(scheme, hostname, port=None):
    if port is None or port == default_ports.get(scheme):
        return "%s://%s" % (scheme, hostname)
    return "%s://%s:%s" % (scheme, hostname, port)


def resolve_ip(hostname):
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


def validate_uaid_hash(uaid, hashed, secret, nonce):
    """Validates that a UAID matches the HMAC value using the supplied
    secret/none"""
    try:
        h = hmac.new(key=secret, msg=uaid+nonce, digestmod=hashlib.sha224)
        return hmac.compare_digest(hashed, h.hexdigest())
    except:
        return False


def generate_uaid_hash(uaid, secret):
    """Generate a HMAC for the uaid using the secret. Returns the HMAC hash
    and the nonce used as a tuple (nonce, hash)."""
    nonce = uuid.uuid4().hex
    h = hmac.new(key=secret, msg=uaid+nonce, digestmod=hashlib.sha224)
    return nonce, h.hexdigest()
