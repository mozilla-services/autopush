from OpenSSL import SSL
from twisted.internet import ssl


class AutopushSSLContextFactory(ssl.DefaultOpenSSLContextFactory):
    def cacheContext(self):
        if self._context is None:
            ctx = self._contextFactory(self.sslmethod)
            ctx.set_options(SSL.OP_NO_SSLv2)
            ctx.set_options(SSL.OP_NO_SSLv3)
            ctx.use_certificate_chain_file(self.certificateFileName)
            ctx.use_privatekey_file(self.privateKeyFileName)
            self._context = ctx
