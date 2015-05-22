"""Router interface"""
from autopush.exceptions import AutopushException


class RouterException(AutopushException):
    """Exception if routing has failed, may include a custom status_code and
    body to write to the response"""
    def __init__(self, message, status_code=500, response_body=""):
        super(AutopushException, self).__init__(message)
        self.status_code = status_code
        self.response_body = response_body or message


class RouterResponse(object):
    def __init__(self, status_code=200, response_body=""):
        self.status_code = status_code
        self.response_body = response_body


class IRouter(object):
    def initialize(self, settings):
        """Initialize the Router to handle a notification with the given
        settings"""
        raise NotImplementedError()

    def route_notification(self, notification):
        """Route a notification

        Return a RouterResponse upon successful routing, or raise a
        RouterException if routing has failed.

        This function runs in the main reactor, if a yield is needed then a
        deferred must be returned.

        """
