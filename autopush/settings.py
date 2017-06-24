"""Autopush Settings Object and Setup"""
import json
import socket
from argparse import Namespace  # noqa
from hashlib import sha256
from typing import Any  # noqa

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import constant_time
from twisted.web.client import _HTTP11ClientFactory

import autopush.db as db
from autopush.exceptions import (
    InvalidSettings,
    InvalidTokenException,
    VapidAuthException
)
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


class QuietClientFactory(_HTTP11ClientFactory):
    """Silence the start/stop factory messages."""
    noisy = False


class AutopushSettings(object):
    """Main Autopush Settings Object"""
    options = ["crypto_key", "hostname", "min_ping_interval",
               "max_data"]

    def __init__(self,
                 crypto_key=None,
                 datadog_api_key=None,
                 datadog_app_key=None,
                 datadog_flush_interval=None,
                 hostname=None,
                 port=None,
                 router_scheme=None,
                 router_hostname=None,
                 router_port=None,
                 endpoint_scheme=None,
                 endpoint_hostname=None,
                 endpoint_port=None,
                 proxy_protocol_port=None,
                 memusage_port=None,
                 router_conf=None,
                 router_tablename="router",
                 router_read_throughput=5,
                 router_write_throughput=5,
                 storage_tablename="storage",
                 storage_read_throughput=5,
                 storage_write_throughput=5,
                 message_tablename="message",
                 message_read_throughput=5,
                 message_write_throughput=5,
                 statsd_host="localhost",
                 statsd_port=8125,
                 resolve_hostname=False,
                 max_data=4096,
                 # Reflected up from UDP Router
                 wake_timeout=0,
                 env='development',
                 enable_cors=False,
                 hello_timeout=0,
                 bear_hash_key=None,
                 preflight_uaid="deadbeef00000000deadbeef00000000",
                 ami_id=None,
                 msg_limit=100,
                 debug=False,
                 connect_timeout=0.5,
                 ssl_key=None,
                 ssl_cert=None,
                 ssl_dh_param=None,
                 router_ssl_key=None,
                 router_ssl_cert=None,
                 client_certs=None,
                 auto_ping_interval=None,
                 auto_ping_timeout=None,
                 max_connections=None,
                 close_handshake_timeout=None,
                 ):
        """Initialize the Settings object

        Upon creation, the HTTP agent will initialize, all configured routers
        will be setup and started, logging will be started, and the database
        will have a preflight check done.

        """
        self.debug = debug

        self.connect_timeout = connect_timeout

        if not crypto_key:
            crypto_key = [Fernet.generate_key()]
        if not isinstance(crypto_key, list):
            crypto_key = [crypto_key]
        self.update(crypto_key=crypto_key)
        self.crypto_key = crypto_key

        if bear_hash_key is None:
            bear_hash_key = []
        if not isinstance(bear_hash_key, list):
            bear_hash_key = [bear_hash_key]
        self.bear_hash_key = bear_hash_key

        self.max_data = max_data

        # Setup hosts/ports/urls
        default_hostname = socket.gethostname()
        self.hostname = hostname or default_hostname
        if resolve_hostname:
            self.hostname = resolve_ip(self.hostname)

        self.datadog_api_key = datadog_api_key
        self.datadog_app_key = datadog_app_key
        self.datadog_flush_interval = datadog_flush_interval
        self.statsd_host = statsd_host
        self.statsd_port = statsd_port

        self.port = port
        self.router_port = router_port
        self.proxy_protocol_port = proxy_protocol_port
        self.memusage_port = memusage_port
        self.endpoint_hostname = endpoint_hostname or self.hostname
        self.router_hostname = router_hostname or self.hostname

        if router_conf is None:
            router_conf = {}
        self.router_conf = router_conf
        self.router_url = canonical_url(
            router_scheme or 'http',
            self.router_hostname,
            router_port
        )

        self.endpoint_url = canonical_url(
            endpoint_scheme or 'http',
            self.endpoint_hostname,
            endpoint_port
        )

        # not accurate under autoendpoint (like router_url)
        self.ws_url = "{}://{}:{}/".format(
            "wss" if ssl_key else "ws",
            self.hostname,
            self.port
        )

        self.ssl_key = ssl_key
        self.ssl_cert = ssl_cert
        self.ssl_dh_param = ssl_dh_param
        self.router_ssl_key = router_ssl_key
        self.router_ssl_cert = router_ssl_cert

        self.enable_tls_auth = client_certs is not None
        self.client_certs = client_certs

        self.auto_ping_interval = auto_ping_interval
        self.auto_ping_timeout = auto_ping_timeout
        self.max_connections = max_connections
        self.close_handshake_timeout = close_handshake_timeout

        self.router_tablename = router_tablename
        self.router_read_throughput = router_read_throughput
        self.router_write_throughput = router_write_throughput
        self.storage_tablename = storage_tablename
        self.storage_read_throughput = storage_read_throughput
        self.storage_write_throughput = storage_write_throughput
        self.message_tablename = message_tablename
        self.message_read_throughput = message_read_throughput
        self.message_write_throughput = message_write_throughput

        self.msg_limit = msg_limit

        # CORS
        self.cors = enable_cors

        # Force timeout in idle seconds
        self.wake_timeout = wake_timeout

        # Env
        self.env = env

        self.hello_timeout = hello_timeout

        self.ami_id = ami_id

        # Generate messages per legacy rules, only used for testing to
        # generate legacy data.
        self._notification_legacy = False
        self.preflight_uaid = preflight_uaid

    @classmethod
    def from_argparse(cls, ns, **kwargs):
        # type: (Namespace, **Any) -> AutopushSettings
        """Create an instance from argparse/additional kwargs"""
        router_conf = {}
        if ns.key_hash:
            db.key_hash = ns.key_hash
        # Some routers require a websocket to timeout on idle
        # (e.g. UDP)
        if ns.wake_pem is not None and ns.wake_timeout != 0:
            router_conf["simplepush"] = {"idle": ns.wake_timeout,
                                         "server": ns.wake_server,
                                         "cert": ns.wake_pem}
        if ns.apns_creds:
            # if you have the critical elements for each external
            # router, create it
            try:
                router_conf["apns"] = json.loads(ns.apns_creds)
            except (ValueError, TypeError):
                raise InvalidSettings(
                    "Invalid JSON specified for APNS config options")
        if ns.gcm_enabled:
            # Create a common gcmclient
            try:
                sender_ids = json.loads(ns.senderid_list)
            except (ValueError, TypeError):
                raise InvalidSettings(
                    "Invalid JSON specified for senderid_list")
            try:
                # This is an init check to verify that things are
                # configured correctly. Otherwise errors may creep in
                # later that go unaccounted.
                sender_ids[sender_ids.keys()[0]]
            except (IndexError, TypeError):
                raise InvalidSettings("No GCM SenderIDs specified or found.")
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
                raise InvalidSettings(
                    "Invalid JSON specified for client_certs")
            if client_certs_arg:
                if not ns.ssl_key:
                    raise InvalidSettings("client_certs specified without SSL "
                                          "enabled (no ssl_key specified)")
                client_certs = {}
                for name, sigs in client_certs_arg.iteritems():
                    if not isinstance(sigs, list):
                        raise InvalidSettings(
                            "Invalid JSON specified for client_certs")
                    for sig in sigs:
                        sig = sig.upper()
                        if (not name or not CLIENT_SHA256_RE.match(sig) or
                                sig in client_certs):
                            raise InvalidSettings(
                                "Invalid client_certs argument")
                        client_certs[sig] = name

        if ns.fcm_enabled:
            # Create a common gcmclient
            if not ns.fcm_auth:
                raise InvalidSettings("No Authorization Key found for FCM")
            if not ns.fcm_senderid:
                raise InvalidSettings("No SenderID found for FCM")
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
            router_tablename=ns.router_tablename,
            storage_tablename=ns.storage_tablename,
            storage_read_throughput=ns.storage_read_throughput,
            storage_write_throughput=ns.storage_write_throughput,
            message_tablename=ns.message_tablename,
            message_read_throughput=ns.message_read_throughput,
            message_write_throughput=ns.message_write_throughput,
            router_read_throughput=ns.router_read_throughput,
            router_write_throughput=ns.router_write_throughput,
            resolve_hostname=ns.resolve_hostname,
            wake_timeout=ns.wake_timeout,
            ami_id=ami_id,
            client_certs=client_certs,
            msg_limit=ns.msg_limit,
            connect_timeout=ns.connection_timeout,
            memusage_port=ns.memusage_port,
            ssl_key=ns.ssl_key,
            ssl_cert=ns.ssl_cert,
            ssl_dh_param=ns.ssl_dh_param,
            **kwargs
        )

    def update(self, **kwargs):
        """Update the arguments, if a ``crypto_key`` is in kwargs then the
        ``self.fernet`` attribute will be initialized"""
        for key, val in kwargs.items():
            if key == "crypto_key":
                fkeys = []
                if not isinstance(val, list):
                    val = [val]
                for v in val:
                    fkeys.append(Fernet(v))
                self.fernet = MultiFernet(fkeys)
            else:
                setattr(self, key, val)

    def make_simplepush_endpoint(self, uaid, chid):
        """Create a simplepush endpoint"""
        root = self.endpoint_url + "/spush/"
        base = (uaid.replace('-', '').decode("hex") +
                chid.replace('-', '').decode("hex"))
        return root + 'v1/' + self.fernet.encrypt(base).strip('=')

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
            metrics.increment("updates.notification.auth.{}".format(
                vapid_auth['scheme']
            ))
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
