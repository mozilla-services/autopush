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
