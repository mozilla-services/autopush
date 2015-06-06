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
        raise NotImplementedError("initialize must be implemented")

    def register(self, uaid, connect):
        """Register the uaid with the connect dict however is preferred and
        return a dict that will be stored as routing_data for this user in the
        future.

        This method must perform validation of the data to store.

        """
        raise NotImplementedError("register must be implemented")

    def route_notification(self, notification, routing_data):
        """Route a notification

        :param notification: A :class:`~autopush.endpoint.Notificaiton`
                             instance.
        :param uaid_data: A dict of the full uaid data from the db.
        :returns: A :class:`RouterResponse` object upon successful routing.
        :raises: A :class:`RouterException` if routing fails.

        This function runs in the main reactor, if a yield is needed then a
        deferred must be returned for the callback chain.

        """
        raise NotImplementedError("route_notification must be implemented")
