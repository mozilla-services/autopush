"""A small collection of Autopush utility functions"""
import base64
import hashlib
import hmac
import re
import socket
import time
import uuid

import ecdsa
import requests
from attr import (
    Factory,
    attrs,
    attrib
)
from jose import jwt
from ua_parser import user_agent_parser

from autopush.exceptions import InvalidTokenException


# Remove trailing padding characters from complex header items like
# Crypto-Key and Encryption
STRIP_PADDING = re.compile('=+(?=[,;]|$)')


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

CLIENT_SHA256_RE = re.compile("""\
^
([0-9A-F]{2}:){31}
 [0-9A-F]{2}
$
""", re.VERBOSE)


def normalize_id(ident):
    if (len(ident) == 36 and
            ident[8] == ident[13] == ident[18] == ident[23] == '-'):
        return ident.lower()
    raw = filter(lambda x: x in '0123456789abcdef', ident.lower())
    if len(raw) != 32:
        raise ValueError("Invalid UUID")
    return '-'.join((raw[:8], raw[8:12], raw[12:16], raw[16:20], raw[20:]))


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
    key_data = base64url_decode(key_data)
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
    return jwt.decode(token, dict(keys=[vk]), options=dict(
        verify_aud=False,
        verify_sub=False,
        verify_exp=False,
    ))


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


@attrs(slots=True)
class WebPushNotification(object):
    """WebPush Notification

    This object centralizes all logic involving the addressing of a single
    WebPush Notification.

    message_id serves a complex purpose. It's returned as the Location header
    value so that an application server may delete the message. It's used as
    part of the non-versioned sort-key. Due to this, its an encrypted value
    that contains the necessary information to derive the location of this
    precise message in the appropriate message table.

    """
    uaid = attrib()  # type: uuid.UUID
    channel_id = attrib()  # type: uuid.UUID
    ttl = attrib()  # type: int
    data = attrib(default=None)
    headers = attrib(default=None)  # type: dict
    timestamp = attrib(default=Factory(lambda: int(time.time())))
    topic = attrib(default=None)

    message_id = attrib(default=None)  # type: str

    # Not an alias for message_id, for backwards compat and cases where an old
    # message with any update_id should be removed.
    update_id = attrib(default=None)  # type: str

    def generate_message_id(self, fernet):
        """Generate a message-id suitable for accessing the message

        For non-topic messages, no sort_key version is currently used and the
        message-id is:

            Encrypted(m : uaid.hex : channel_id.hex)

        For topic messages, a sort_key version of 01 is used, and the topic
        is included for reference:

            Encrypted(01 : uaid.hex : channel_id.hex : topic)

        This is a blocking call.

        :type fernet: cryptography.fernet.Fernet

        """
        if self.topic:
            msg_key = ":".join(["01", self.uaid.hex, self.channel_id.hex,
                                self.topic])
        else:
            msg_key = ":".join(["m", self.uaid.hex, self.channel_id.hex])
        self.message_id = fernet.encrypt(msg_key.encode('utf8'))
        self.update_id = self.message_id
        return self.message_id

    @staticmethod
    def parse_decrypted_message_id(decrypted_token):
        """Parses a decrypted message-id into component parts

        :type decrypted_token: str
        :rtype: dict

        """
        topic = None
        if decrypted_token.startswith("01:"):
            info = decrypted_token.split(":")
            if len(info) != 4:
                raise InvalidTokenException("Incorrect number of token parts.")
            api_ver, uaid, chid, topic = info
        else:
            info = decrypted_token.split(":")
            if len(info) != 3:
                raise InvalidTokenException("Incorrect number of token parts.")
            kind, uaid, chid = decrypted_token.split(":")
            if kind != "m":
                raise InvalidTokenException("Incorrect token kind.")
        return dict(
            uaid=uaid,
            chid=chid,
            topic=topic,
        )

    def cleanup_headers(self):
        """Sanitize the headers for this notification

        This only needs to be run when creating a notification from passed
        in application server headers.

        """
        headers = self.headers
        # Strip crypto/encryption headers down
        for hdr in ["crypto-key", "encryption"]:
            if STRIP_PADDING.search(headers.get(hdr, "")):
                head = headers[hdr].replace('"', '')
                headers[hdr] = STRIP_PADDING.sub("", head)

        data = dict(
            encoding=headers["content-encoding"],
            encryption=headers["encryption"],
        )
        # AWS cannot store empty strings, so we only add these keys if
        # they're present to avoid empty strings.
        for name in ["encryption-key", "crypto-key"]:
            if name in headers:
                # NOTE: The client code expects all header keys to be lower
                # case and s/-/_/.
                data[name.lower().replace("-", "_")] = headers[name]
        self.headers = data

    @property
    def sort_key(self):
        """Return an appropriate sort_key for this notification"""
        chid = normalize_id(self.channel_id.hex)
        if self.topic:
            return "01:{chid}:{topic}".format(chid=chid, topic=self.topic)
        else:
            return "{chid}:{message_id}".format(chid=chid,
                                                message_id=self.message_id)

    @staticmethod
    def parse_sort_key(sort_key):
        """Parse the sort key from the database

        :type sort_key: str
        :rtype: dict

        """
        topic = None
        message_id = None
        if re.match(r'^\d\d:', sort_key):
            api_ver, channel_id, topic = sort_key.split(":")
        else:
            channel_id, message_id = sort_key.split(":")
            api_ver = "00"
        return dict(api_ver=api_ver, channel_id=channel_id,
                    topic=topic, message_id=message_id)

    @property
    def location(self):
        """Return an appropriate value for the Location header"""
        return self.message_id

    def expired(self, at_time=None):
        """Indicates whether the message has expired or not

        :param at_time: Optional time to compare for expiration
        :type at_time: int

        """
        now = at_time or int(time.time())
        return now >= (self.ttl + self.timestamp)

    @classmethod
    def from_message_table(cls, uaid, item):
        """Create a WebPushNotification from a message table item

        :type uaid: uuid.UUID
        :type item: dict or boto.dynamodb2.item.Item

        :rtype: WebPushNotification

        """
        key_info = cls.parse_sort_key(item["chidmessageid"])
        if key_info.get("topic"):
            key_info["message_id"] = item["updateid"]

        return cls(uaid=uaid, channel_id=uuid.UUID(key_info["channel_id"]),
                   data=item.get("data"),
                   headers=item.get("headers"),
                   ttl=item["ttl"],
                   topic=key_info.get("topic"),
                   message_id=key_info["message_id"],
                   update_id=item.get("updateid"),
                   timestamp=item.get("timestamp"),
                   )

    @classmethod
    def from_webpush_request_schema(cls, data, fernet):
        """Create a WebPushNotification from a validated WebPushRequestSchema

        This is a blocking call.

        :type data: autopush.web.push_validation.WebPushRequestSchema
        :type fernet: cryptography.fernet.Fernet

        :rtype: WebPushNotification

        """
        sub = data["subscription"]
        notif = cls(uaid=sub["uaid"], channel_id=sub["chid"],
                    data=data["body"], headers=data["headers"],
                    ttl=data["headers"]["ttl"],
                    topic=data["headers"]["topic"])

        if notif.data:
            notif.cleanup_headers()
        else:
            notif.headers = None

        notif.generate_message_id(fernet)
        return notif

    @classmethod
    def from_message_id(cls, message_id, fernet):
        """Create a WebPushNotification from a message_id

        This is a blocking call.

        The resulting WebPushNotification is not a complete one
        from the database, but has all the parsed attributes
        available that can be derived from the message_id.

        This is suitable for passing to delete calls.

        :type message_id: str
        :type fernet: cryptography.fernet.Fernet

        :rtype: WebPushNotification

        """
        decrypted_message_id = fernet.decrypt(message_id)
        key_info = cls.parse_decrypted_message_id(decrypted_message_id)
        notif = cls(uaid=uuid.UUID(key_info["uaid"]),
                    channel_id=uuid.UUID(key_info["chid"]),
                    data=None,
                    ttl=None,
                    topic=key_info["topic"],
                    message_id=message_id,
                    )
        if key_info["topic"]:
            notif.update_id = message_id
        return notif

    @classmethod
    def from_serialized(cls, uaid, data):
        """Create a WebPushNotification from a deserialized JSON dict

        :type uaid: uuid.UUID
        :type data: dict

        :rtype: WebPushNotification

        """
        notif = cls(uaid=uaid, channel_id=uuid.UUID(data["channelID"]),
                    data=data.get("data"),
                    headers=data.get("headers"),
                    ttl=data.get("ttl"),
                    topic=data.get("topic"),
                    message_id=str(data["version"]),
                    update_id=str(data["version"]),
                    timestamp=data.get("timestamp"),
                    )
        return notif

    @property
    def version(self):
        """Return a 'version' for use with a websocket client

        In our case we use the message-id as its a unique value for every
        message.

        """
        return self.message_id

    def serialize(self):
        """Serialize to a dict for delivery to a connection node"""
        payload = dict(
            channelID=normalize_id(self.channel_id.hex),
            version=self.version,
            ttl=self.ttl,
            topic=self.topic,
            timestamp=self.timestamp,
        )
        if self.data:
            payload["data"] = self.data
            payload["headers"] = self.headers
        return payload

    def websocket_format(self):
        """Format a notification for a websocket client"""
        # Firefox currently requires channelIDs to be '-' formatted.
        payload = dict(
            messageType="notification",
            channelID=normalize_id(self.channel_id.hex),
            version=self.version,
        )
        if self.data:
            payload["data"] = self.data
            payload["headers"] = self.headers
        return payload


def ms_time():
    """Return current time.time call as ms and a Python int"""
    return int(time.time() * 1000)
