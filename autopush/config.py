"""Autopush Config Object and Setup"""
import json
import socket
from argparse import Namespace  # noqa
from hashlib import sha256
from typing import (  # noqa
    Any,
    Dict,
    List,
    Optional,
    Type,
    Union
)

from attr import (
    attrs,
    attrib,
    Factory
)
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import constant_time

import autopush.db as db
from autopush.exceptions import (
    InvalidConfig,
    InvalidTokenException,
    VapidAuthException
)
from autopush.ssl import AutopushSSLContextFactory
from autopush.types import JSONDict  # noqa
from autopush.utils import (
    CLIENT_SHA256_RE,
    canonical_url,
    get_amid,
    resolve_ip,
    repad,
    base64url_decode,
    parse_auth_header,
)
from autopush.crypto_key import CryptoKey, CryptoKeyException


def _init_crypto_key(ck):
    # type: (Optional[Union[str, List[str]]]) -> List[str]
    """Provide a default or ensure the provided's a list"""
    if ck is None:
        return [Fernet.generate_key()]
    return ck if isinstance(ck, list) else [ck]


def _nested(cls, **kwargs):
    # type: (Type, **Any) -> Any
    """Defines an attr cls nested within another attr.

    This attribute constructs the nested attr from a dict argument
    (representing its kwargs) unless already an instance of cls.

    """
    def converter(arg):
        return arg if isinstance(arg, cls) else cls(**arg)
    return attrib(convert=converter, **kwargs)


@attrs
class SSLConfig(object):
    """AutopushSSLContextFactory configuration"""

    key = attrib(default=None)  # type: Optional[str]
    cert = attrib(default=None)  # type: Optional[str]
    dh_param = attrib(default=None)  # type: Optional[str]

    def cf(self, **kwargs):
        # type: (**Any) -> Optional[AutopushSSLContextFactory]
        """Build our AutopushSSLContextFactory (if configured)"""
        if not self.key:
            return None
        return AutopushSSLContextFactory(
            self.key,
            self.cert,
            dh_file=self.dh_param,
            **kwargs
        )


@attrs
class DDBTableConfig(object):
    """A DynamoDB Table's configuration"""

    tablename = attrib()  # type: str
    read_throughput = attrib(default=5)  # type: int
    write_throughput = attrib(default=5)  # type: int


@attrs
class AutopushConfig(object):
    """Main Autopush Settings Object"""

    debug = attrib(default=False)  # type: bool

    fernet = attrib(init=False)  # type: MultiFernet
    _crypto_key = attrib(
        convert=_init_crypto_key, default=None)  # type: List[str]

    bear_hash_key = attrib(default=Factory(list))  # type: List[str]

    hostname = attrib(default=None)  # type: Optional[str]
    port = attrib(default=None)  # type: Optional[int]
    _resolve_hostname = attrib(default=False)  # type: bool

    router_scheme = attrib(default=None)  # type: Optional[str]
    router_hostname = attrib(default=None)  # type: Optional[str]
    router_port = attrib(default=None)  # type: Optional[int]

    endpoint_scheme = attrib(default=None)  # type: Optional[str]
    endpoint_hostname = attrib(default=None)  # type: Optional[str]
    endpoint_port = attrib(default=None)  # type: Optional[int]

    proxy_protocol_port = attrib(default=None)  # type: Optional[int]
    memusage_port = attrib(default=None)  # type: Optional[int]

    statsd_host = attrib(default="localhost")  # type: str
    statsd_port = attrib(default=8125)  # type: int

    datadog_api_key = attrib(default=None)  # type: Optional[str]
    datadog_app_key = attrib(default=None)  # type: Optional[str]
    datadog_flush_interval = attrib(default=None)  # type: Optional[int]

    router_table = _nested(
        DDBTableConfig,
        default=dict(tablename="router")
    )  # type: DDBTableConfig
    message_table = _nested(
        DDBTableConfig,
        default=dict(tablename="message")
    )  # type: DDBTableConfig

    preflight_uaid = attrib(
        default="deadbeef00000000deadbeef00000000")  # type: str

    ssl = _nested(SSLConfig, default=Factory(SSLConfig))  # type: SSLConfig
    router_ssl = _nested(
        SSLConfig, default=Factory(SSLConfig))  # type: SSLConfig
    client_certs = attrib(default=None)  # type: Optional[Dict[str, str]]

    router_url = attrib(init=False)  # type: str
    endpoint_url = attrib(init=False)  # type: str
    ws_url = attrib(init=False)  # type: str

    router_conf = attrib(default=Factory(dict))  # type: JSONDict

    # twisted Agent's connectTimeout
    connect_timeout = attrib(default=0.5)  # type: float
    max_data = attrib(default=4096)  # type: int
    env = attrib(default='development')  # type: str
    ami_id = attrib(default=None)  # type: Optional[str]
    cors = attrib(default=False)  # type: bool

    hello_timeout = attrib(default=0)  # type: int
    # Force timeout in idle seconds
    msg_limit = attrib(default=100)  # type: int
    auto_ping_interval = attrib(default=None)  # type: Optional[int]
    auto_ping_timeout = attrib(default=None)  # type: Optional[int]
    max_connections = attrib(default=None)  # type: Optional[int]
    close_handshake_timeout = attrib(default=None)  # type: Optional[int]

    # Generate messages per legacy rules, only used for testing to
    # generate legacy data.
    _notification_legacy = attrib(default=False)  # type: bool

    # Use the cryptography library
    use_cryptography = attrib(default=False)  # type: bool

    # Strict-Transport-Security max age (Default 1 year in secs)
    sts_max_age = attrib(default=31536000)  # type: int

    def __attrs_post_init__(self):
        """Initialize the Settings object"""
        # Setup hosts/ports/urls
        if not self.hostname:
            self.hostname = socket.gethostname()
        if self._resolve_hostname:
            self.hostname = resolve_ip(self.hostname)

        if not self.endpoint_hostname:
            self.endpoint_hostname = self.hostname
        if not self.router_hostname:
            self.router_hostname = self.hostname

        self.router_url = canonical_url(
            self.router_scheme or 'http',
            self.router_hostname,
            self.router_port
        )
        self.endpoint_url = canonical_url(
            self.endpoint_scheme or 'http',
            self.endpoint_hostname,
            self.endpoint_port
        )
        # not accurate under autoendpoint (like router_url)
        self.ws_url = "{}://{}:{}/".format(
            'wss' if self.ssl.key else 'ws',
            self.hostname,
            self.port
        )

        self.fernet = MultiFernet([Fernet(key) for key in self._crypto_key])

    @property
    def enable_tls_auth(self):
        """Whether TLS authentication w/ client certs is enabled"""
        return self.client_certs is not None

    @classmethod
    def from_argparse(cls, ns, **kwargs):
        # type: (Namespace, **Any) -> AutopushConfig
        """Create an instance from argparse/additional kwargs"""
        router_conf = {}
        if ns.key_hash:
            db.key_hash = ns.key_hash
        if ns.apns_creds:
            # if you have the critical elements for each external
            # router, create it
            try:
                router_conf["apns"] = json.loads(ns.apns_creds)
            except (ValueError, TypeError):
                raise InvalidConfig(
                    "Invalid JSON specified for APNS config options")
        if ns.gcm_enabled:
            # Create a common gcmclient
            try:
                sender_ids = json.loads(ns.senderid_list)
            except (ValueError, TypeError):
                raise InvalidConfig("Invalid JSON specified for senderid_list")
            try:
                # This is an init check to verify that things are
                # configured correctly. Otherwise errors may creep in
                # later that go unaccounted.
                sender_ids[sender_ids.keys()[0]]
            except (IndexError, TypeError):
                raise InvalidConfig("No GCM SenderIDs specified or found.")
            router_conf["gcm"] = {"ttl": ns.gcm_ttl,
                                  "dryrun": ns.gcm_dryrun,
                                  "max_data": ns.max_data,
                                  "collapsekey": ns.gcm_collapsekey,
                                  "senderIDs": sender_ids}

        client_certs = None
        # endpoint only
        if getattr(ns, 'client_certs', None):
            try:
                client_certs_arg = json.loads(ns.client_certs)
            except (ValueError, TypeError):
                raise InvalidConfig("Invalid JSON specified for client_certs")
            if client_certs_arg:
                if not ns.ssl_key:
                    raise InvalidConfig("client_certs specified without SSL "
                                        "enabled (no ssl_key specified)")
                client_certs = {}
                for name, sigs in client_certs_arg.iteritems():
                    if not isinstance(sigs, list):
                        raise InvalidConfig(
                            "Invalid JSON specified for client_certs")
                    for sig in sigs:
                        sig = sig.upper()
                        if (not name or not CLIENT_SHA256_RE.match(sig) or
                                sig in client_certs):
                            raise InvalidConfig(
                                "Invalid client_certs argument")
                        client_certs[sig] = name

        if ns.fcm_enabled:
            # Create a common gcmclient
            if not ns.fcm_auth:
                raise InvalidConfig("No Authorization Key found for FCM")
            if not ns.fcm_senderid:
                raise InvalidConfig("No SenderID found for FCM")
            router_conf["fcm"] = {"ttl": ns.fcm_ttl,
                                  "dryrun": ns.fcm_dryrun,
                                  "max_data": ns.max_data,
                                  "collapsekey": ns.fcm_collapsekey,
                                  "auth": ns.fcm_auth,
                                  "senderid": ns.fcm_senderid}

        ami_id = None
        # Not a fan of double negatives, but this makes more
        # understandable args
        if not ns.no_aws:
            ami_id = get_amid()

        return cls(
            crypto_key=ns.crypto_key,
            datadog_api_key=ns.datadog_api_key,
            datadog_app_key=ns.datadog_app_key,
            datadog_flush_interval=ns.datadog_flush_interval,
            hostname=ns.hostname,
            statsd_host=ns.statsd_host,
            statsd_port=ns.statsd_port,
            router_conf=router_conf,
            resolve_hostname=ns.resolve_hostname,
            ami_id=ami_id,
            client_certs=client_certs,
            msg_limit=ns.msg_limit,
            connect_timeout=ns.connection_timeout,
            memusage_port=ns.memusage_port,
            use_cryptography=ns.use_cryptography,
            router_table=dict(
                tablename=ns.router_tablename,
                read_throughput=ns.router_read_throughput,
                write_throughput=ns.router_write_throughput
            ),
            message_table=dict(
                tablename=ns.message_tablename,
                read_throughput=ns.message_read_throughput,
                write_throughput=ns.message_write_throughput
            ),
            ssl=dict(
                key=ns.ssl_key,
                cert=ns.ssl_cert,
                dh_param=ns.ssl_dh_param
            ),
            sts_max_age=ns.sts_max_age,
            **kwargs
        )

    def make_endpoint(self, uaid, chid, key=None):
        """Create an v1 or v2 WebPush endpoint from the identifiers.

        Both endpoints use bytes instead of hex to reduce ID length.
        v1 is the uaid + chid
        v2 is the uaid + chid + sha256(key).bytes

        :param uaid: User Agent Identifier
        :param chid: Channel or Subscription ID
        :param key: Optional Base64 URL-encoded application server key
        :returns: Push endpoint

        """
        root = self.endpoint_url + '/wpush/'
        base = (uaid.replace('-', '').decode("hex") +
                chid.replace('-', '').decode("hex"))

        if key is None:
            return root + 'v1/' + self.fernet.encrypt(base).strip('=')

        raw_key = base64url_decode(key.encode('utf8'))
        ep = self.fernet.encrypt(base + sha256(raw_key).digest()).strip('=')
        return root + 'v2/' + ep

    def parse_endpoint(self, metrics, token, version="v1", ckey_header=None,
                       auth_header=None):
        """Parse an endpoint into component elements of UAID, CHID and optional
        key hash if v2

        :param token: The obscured subscription data.
        :param version: This is the API version of the token.
        :param ckey_header: the Crypto-Key header bearing the public key
            (from Crypto-Key: p256ecdsa=)
        :param auth_header: The Authorization header bearing the VAPID info

        :raises ValueError: In the case of a malformed endpoint.

        :returns: a dict containing (uaid=UAID, chid=CHID, public_key=KEY)

        """
        token = self.fernet.decrypt(repad(token).encode('utf8'))
        public_key = None
        if ckey_header:
            try:
                crypto_key = CryptoKey(ckey_header)
            except CryptoKeyException:
                raise InvalidTokenException("Invalid key data")
            public_key = crypto_key.get_label('p256ecdsa')
        if auth_header:
            vapid_auth = parse_auth_header(auth_header)
            if not vapid_auth:
                raise VapidAuthException("Invalid Auth token")
            metrics.increment("notification.auth",
                              tags="vapid:{version},scheme:{scheme}".format(
                                  **vapid_auth
                              ).split(","))
            # pull the public key from the VAPID auth header if needed
            try:
                if vapid_auth['version'] != 1:
                    public_key = vapid_auth['k']
            except KeyError:
                raise VapidAuthException("Missing Public Key")
        if version == 'v1' and len(token) != 32:
            raise InvalidTokenException("Corrupted push token")
        if version == 'v2':
            if not auth_header:
                raise VapidAuthException("Missing Authorization Header")
            if len(token) != 64:
                raise InvalidTokenException("Corrupted push token")
            if not public_key:
                raise VapidAuthException("Invalid key data")
            try:
                decoded_key = base64url_decode(public_key)
            except TypeError:
                raise VapidAuthException("Invalid key data")
            if not constant_time.bytes_eq(sha256(decoded_key).digest(),
                                          token[32:]):
                raise VapidAuthException("Key mismatch")
        return dict(uaid=token[:16].encode('hex'),
                    chid=token[16:32].encode('hex'),
                    version=version,
                    public_key=public_key)
