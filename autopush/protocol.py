from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.web.client import ResponseDone


class IgnoreBody(Protocol):
    """A protocol that discards any data it receives.

    This is necessary to support persistent HTTP connections. If the
    response body is never read using ``Response.deliverBody``, or
    ``stopProducing()`` is called, the connection will not be reused.
    """
    def __init__(self, response, deferred):
        self.response = response
        self.deferred = deferred

    @classmethod
    def ignore(cls, response):
        d = Deferred()
        response.deliverBody(cls(response, d))
        return d

    def dataReceived(self, data):
        pass

    def connectionLost(self, reason):
        if reason.check(ResponseDone):
            self.deferred.callback(self.response)
        else:
            self.deferred.errback(reason)
        del self.response
        del self.deferred
