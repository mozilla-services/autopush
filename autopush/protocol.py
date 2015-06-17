"""Basic Protocol for ignoring data"""
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
        """Class method helper for ignoring the response"""
        d = Deferred()
        response.deliverBody(cls(response, d))
        return d

    def dataReceived(self, data):
        """Ignore received data"""
        pass

    def connectionLost(self, reason):
        """Relay back the loss of connection to the deferred"""
        if reason.check(ResponseDone):
            self.deferred.callback(self.response)
        else:
            self.deferred.errback(reason)
        del self.response
        del self.deferred
