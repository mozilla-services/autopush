"""Custom SSL configuration"""
from OpenSSL import SSL
from twisted.internet import ssl

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
    """A SSL context factory"""
    def cacheContext(self):
        """Setup the main context factory with custom SSL settings."""
        if self._context is None:
            ctx = self._contextFactory(self.sslmethod)

            ctx.set_cipher_list(MOZILLA_INTERMEDIATE_CIPHERS)
            ctx.set_options(SSL.OP_CIPHER_SERVER_PREFERENCE)
            ctx.set_options(SSL.OP_NO_SSLv2)
            ctx.set_options(SSL.OP_NO_SSLv3)
            ctx.set_options(SSL.OP_NO_COMPRESSION)
            ctx.set_options(SSL.MODE_RELEASE_BUFFERS)
            ctx.set_options(SSL.OP_ALL & ~SSL.OP_MICROSOFT_BIG_SSLV3_BUFFER)

            ctx.use_certificate_chain_file(self.certificateFileName)
            ctx.use_privatekey_file(self.privateKeyFileName)

            self._context = ctx
