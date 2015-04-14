from OpenSSL import SSL
from twisted.internet import ssl
from twisted.python import log

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


class AutopushSSLContextFactory(ssl.DefaultOpenSSLContextFactory):
    def cacheContext(self):
        if self._context is None:
            ctx = self._contextFactory(self.sslmethod)

            ctx.set_cipher_list(MOZILLA_INTERMEDIATE_CIPHERS)
            ctx.set_options(SSL.OP_CIPHER_SERVER_PREFERENCE)
            ctx.set_options(SSL.OP_NO_SSLv2)
            ctx.set_options(SSL.OP_NO_SSLv3)

            disableSSLCompression()

            ctx.use_certificate_chain_file(self.certificateFileName)
            ctx.use_privatekey_file(self.privateKeyFileName)

            self._context = ctx


def disableSSLCompression():
    try:
        import ctypes
        import glob
        openssl = ctypes.CDLL(None, ctypes.RTLD_GLOBAL)
        try:
            f = openssl.SSL_COMP_get_compression_methods # flake8: noqa
        except AttributeError:
            ssllib = sorted(glob.glob("/usr/lib/libssl.so.*"))[0]
            openssl = ctypes.CDLL(ssllib, ctypes.RTLD_GLOBAL)

        openssl.SSL_COMP_get_compression_methods.restype = ctypes.c_void_p
        openssl.sk_zero.argtypes = [ctypes.c_void_p]
        openssl.sk_zero(openssl.SSL_COMP_get_compression_methods())
    except Exception, e:
        log.msg('disableSSLCompression: Failed:')
        log.msg(e)
