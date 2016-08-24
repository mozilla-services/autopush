"""A small collection of Autopush utility functions"""
import base64
import hashlib
import hmac
import json
import socket
import uuid

import ecdsa
import requests
from jose import jws
from twisted.logger import Logger
from twisted.python import failure
from ua_parser import user_agent_parser


# List of valid user-agent attributes to keep, anything not in this list is
# considered 'Other'. We log the user-agent on connect always to retain the
# full string, but for DD more tags are expensive so we limit to these.
VALID_UA_BROWSER = ["Chrome", "Firefox", "Safari", "Opera"]
# See test_os.yaml in github.com/ua-parser/uap-core for full list
# We special case Windows since it has 8 values, and we only care that its
# Windows
VALID_UA_OS = ["Firefox OS", "Linux", "Mac OS X"]

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
            if uuid.UUID(uaid).hex == uaid:
                return True, uaid
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
        string += '===='[len(string) % 4:]
    return string


def base64url_decode(string):
    """Decodes a Base64 URL-encoded string per RFC 7515.

    RFC 7515 (used for Encrypted Content-Encoding and JWT) requires unpadded
    encoded strings, but Python's ``urlsafe_b64decode`` only accepts padded
    strings.
    """
    return base64.urlsafe_b64decode(repad(string))


def get_amid():
    """Fetch the AMI instance ID

    """
    try:
        resp = requests.get(
            "http://169.254.169.254/latest/meta-data/ami-id",
            timeout=1)
        return resp.content
    except (requests.HTTPError, requests.ConnectionError):
        return "Unknown"


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
    # jose offers jwt.decode(token, vk, ...) which does a full check
    # on the JWT object. Vapid is a bit more creative in how it
    # stores data into a JWT and breaks expectations. We would have to
    # turn off most of the validation in order for it to be useful.
    return json.loads(jws.verify(token, vk, algorithms=["ES256"]))


def parse_user_agent(agent_string):
    """Extracts user-agent data from a UA string

    Parses the user-agent into two forms. A limited one suitable for Datadog
    logging with limited tags, and a full string suitable for complete logging.

    :returns: A tuple of dicts, the first being the Datadog limited and the
              second being the complete info.
    :rtype: (dict, dict)

    """
    parsed = user_agent_parser.Parse(agent_string)
    dd_info = {}
    raw_info = {}

    # Parse out the OS family
    ua_os = parsed["os"]
    ua_os_family = raw_info["ua_os_family"] = ua_os["family"]
    if ua_os_family.startswith("Windows"):
        # Windows has a bunch of additional version bits in the family string
        dd_info["ua_os_family"] = "Windows"
    elif ua_os_family in VALID_UA_OS:
        dd_info["ua_os_family"] = ua_os_family
    elif "Linux" in agent_string:
        # Incredibly annoying, but the user agent parser returns things like
        # 'Mandriva' and 'Unbuntu' sometimes instead of just saying Linux
        dd_info["ua_os_family"] = "Linux"
    else:
        dd_info["ua_os_family"] = "Other"

    # Parse out the full version for raw info, too many combos for DataDog
    bits = ["major", "minor", "patch", "patch_minor"]
    os_bits = [ua_os[x] for x in bits]
    raw_info["ua_os_ver"] = ".".join(filter(None, os_bits))

    # Parse out the browser family
    ua_browser = parsed["user_agent"]
    ua_browser_family = raw_info["ua_browser_family"] = ua_browser["family"]
    if ua_browser_family in VALID_UA_BROWSER:
        dd_info["ua_browser_family"] = ua_browser_family
    else:
        dd_info["ua_browser_family"] = "Other"

    # Parse out the full browser version
    bits = ["major", "minor", "patch"]
    browser_bits = [ua_browser[x] for x in bits]
    raw_info["ua_browser_ver"] = ".".join(filter(None, browser_bits))

    return dd_info, raw_info


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
