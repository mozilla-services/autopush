from twisted.internet import defer
from twisted.internet.interfaces import IStreamServerEndpoint
from twisted.protocols.haproxy._wrapper import HAProxyWrappingFactory
from twisted.protocols.tls import TLSMemoryBIOFactory
from zope.interface import implementer


@implementer(IStreamServerEndpoint)
class HAProxyServerEndpoint(object):
    """A HAProxy endpoint, optionally handling TLS"""

    wrapper_factory = HAProxyWrappingFactory

    def __init__(self, reactor, port, ssl_cf=None, **kwargs):
        self._reactor = reactor
        self._port = port
        self._ssl_cf = ssl_cf
        self._kwargs = kwargs

    def listen(self, factory):
        """Implement IStreamServerEndpoint.listen to listen on TCP.

        Optionally configuring TLS behind the HAProxy protocol.

        """
        if self._ssl_cf:
            factory = TLSMemoryBIOFactory(self._ssl_cf, False, factory)
        proxyf = self.wrapper_factory(factory)
        return defer.execute(self._listen, self._port, proxyf, **self._kwargs)

    def _listen(self, *args, **kwargs):
        port = self._reactor.listenTCP(*args, **kwargs)
        if self._ssl_cf:
            port._type = 'TLS'
        return port
