"""Custom SSL configuration"""
from __future__ import absolute_import
import socket  # noqa
import ssl
from typing import (  # noqa
    Any,
    Dict,
    FrozenSet,
    Optional,
    Tuple,
)

from OpenSSL import SSL
from twisted.internet.ssl import DefaultOpenSSLContextFactory

MOZILLA_INTERMEDIATE_CIPHERS = (
    'ECDHE-RSA-AES128-GCM-SHA256:'
    'ECDHE-ECDSA-AES128-GCM-SHA256:'
    'ECDHE-RSA-AES256-GCM-SHA384:'
    'ECDHE-ECDSA-AES256-GCM-SHA384:'
    'DHE-RSA-AES128-GCM-SHA256:'
    'DHE-DSS-AES128-GCM-SHA256:'
    'ECDHE-RSA-AES128-SHA256:'
    'ECDHE-ECDSA-AES128-SHA256:'
    'ECDHE-RSA-AES128-SHA:'
    'ECDHE-ECDSA-AES128-SHA:'
    'ECDHE-RSA-AES256-SHA384:'
    'ECDHE-ECDSA-AES256-SHA384:'
    'ECDHE-RSA-AES256-SHA:'
    'ECDHE-ECDSA-AES256-SHA:'
    'DHE-RSA-AES128-SHA256:'
    'DHE-RSA-AES128-SHA:'
    'DHE-DSS-AES128-SHA256:'
    'DHE-RSA-AES256-SHA256:'
    'DHE-DSS-AES256-SHA:'
    'DHE-RSA-AES256-SHA:'
    'AES128-GCM-SHA256:'
    'AES256-GCM-SHA384:'
    'AES128-SHA256:'
    'AES256-SHA256:'
    'AES128-SHA:'
    'AES256-SHA:'
    'AES:'
    'CAMELLIA:DES-CBC3-SHA:'
    '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:'
    '!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA'
)


class AutopushSSLContextFactory(DefaultOpenSSLContextFactory):
    """A SSL context factory"""

    def __init__(self, *args, **kwargs):
        self.dh_file = kwargs.pop('dh_file', None)
        self.require_peer_certs = kwargs.pop('require_peer_certs', False)
        DefaultOpenSSLContextFactory.__init__(self, *args, **kwargs)

    def cacheContext(self):
        """Setup the main context factory with custom SSL settings"""
        if self._context is None:
            ctx = self._contextFactory(self.sslmethod)

            ctx.set_cipher_list(MOZILLA_INTERMEDIATE_CIPHERS)
            ctx.set_options(SSL.OP_CIPHER_SERVER_PREFERENCE)
            ctx.set_options(SSL.OP_NO_SSLv2)
            ctx.set_options(SSL.OP_NO_SSLv3)
            ctx.set_options(SSL.OP_NO_COMPRESSION)
            ctx.set_mode(SSL.MODE_RELEASE_BUFFERS)
            ctx.set_options(SSL.OP_ALL & ~SSL.OP_MICROSOFT_BIG_SSLV3_BUFFER)

            ctx.use_certificate_chain_file(self.certificateFileName)
            ctx.use_privatekey_file(self.privateKeyFileName)

            if self.dh_file:
                ctx.load_tmp_dh(self.dh_file)

            if self.require_peer_certs:
                # Require peer certs but only for use by
                # RequestHandlers
                ctx.set_verify(
                    SSL.VERIFY_PEER |
                    SSL.VERIFY_CLIENT_ONCE,
                    self._allow_peer)

            self._context = ctx

    def _allow_peer(self, conn, cert, errno, depth, preverify_ok):
        # skip verification: we only care about whitelisted signatures
        # on file
        return True


def monkey_patch_ssl_wrap_socket():
    """Replace ssl.wrap_socket with ssl_wrap_socket_cached"""
    ssl.wrap_socket = ssl_wrap_socket_cached


def undo_monkey_patch_ssl_wrap_socket():
    """Undo monkey_patch_ssl_wrap_socket"""
    ssl.wrap_socket = _orig_ssl_wrap_socket


_CacheKey = FrozenSet[Tuple[str, Any]]
_sslcontext_cache = {}  # type: Dict[_CacheKey, ssl.SSLContext]
_orig_ssl_wrap_socket = ssl.wrap_socket


def ssl_wrap_socket_cached(
        sock,                          # type: socket.socket
        keyfile=None,                  # type: Optional[str]
        certfile=None,                 # type: Optional[str]
        server_side=False,             # type: bool
        cert_reqs=ssl.CERT_NONE,       # type: int
        ssl_version=ssl.PROTOCOL_TLS,  # type: int
        ca_certs=None,                 # type: Optional[str]
        do_handshake_on_connect=True,  # type: bool
        suppress_ragged_eofs=True,     # type: bool
        ciphers=None                   # type: Optional[str]
        ):
    # type: (...) -> ssl.SSLSocket
    """ssl.wrap_socket replacement that caches SSLContexts"""
    key_kwargs = (
        ('keyfile', keyfile),
        ('certfile', certfile),
        ('cert_reqs', cert_reqs),
        ('ssl_version', ssl_version),
        ('ca_certs', ca_certs),
        ('ciphers', ciphers),
    )
    key = frozenset(key_kwargs)

    context = _sslcontext_cache.get(key)
    if context is not None:
        return context.wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs
        )

    wrapped = _orig_ssl_wrap_socket(
        sock,
        keyfile=keyfile,
        certfile=certfile,
        server_side=server_side,
        cert_reqs=cert_reqs,
        ssl_version=ssl_version,
        ca_certs=ca_certs,
        do_handshake_on_connect=do_handshake_on_connect,
        suppress_ragged_eofs=suppress_ragged_eofs,
        ciphers=ciphers
    )
    _sslcontext_cache[key] = wrapped.context
    return wrapped
