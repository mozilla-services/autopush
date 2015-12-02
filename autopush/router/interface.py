"""Router interface"""
from autopush.exceptions import AutopushException


class RouterException(AutopushException):
    """Exception if routing has failed, may include a custom status_code and
    body to write to the response.

    """
    def __init__(self, message, status_code=500, response_body="",
                 router_data=None, headers={}, log_exception=True,
                 errno=None):
        """Create a new RouterException"""
        super(AutopushException, self).__init__(message)
        self.status_code = status_code
        self.headers = headers
        self.log_exception = log_exception
        self.response_body = response_body or message
        self.errno = errno


class RouterResponse(object):
    """Router response if routing has succeeded.

    If the router data needs to change as a result of this message, either the
    router got invalidated, or needs updating, then the router_data should be
    set.

    """
    def __init__(self, status_code=200, response_body="", router_data=None,
                 headers={}, errno=None):
        """Create a new RouterResponse"""
        self.status_code = status_code
        self.response_body = response_body
        self.router_data = router_data
        self.headers = headers
        self.errno = errno


class IRouter(object):
    def __init__(self, settings, router_conf):
        """Initialize the Router to handle notifications and registrations with
        the given settings and router conf."""
        raise NotImplementedError("__init__ must be implemented")

    def register(self, uaid, routing_data):
        """Register the uaid with the connect dict however is preferred and
        return a dict that will be stored as routing_data for this user in the
        future.

        :returns: A response object
        :rtype: :class:`RouterResponse`
        :raises:
            :exc:`RouterException` if data supplied is invalid.

        """
        raise NotImplementedError("register must be implemented")

    def amend_msg(self, msg):
        """Modify an outbound response message to include router info

        :param msg: A dict of the response data to be sent to the client
        :returns: A potentially modified dict to return to the client

        Some routers may require additional info to be returned to clients.

        """
        raise NotImplementedError("amend_msg must be implemented")

    def check_token(self, token):
        """Check if a given token is still valid.

        ":param token: A router base token
        ":returns: (ValidBool, AlternateToken)

        """
        raise NotImplementedError("check_token must be implemented")

    def route_notification(self, notification, uaid_data):
        """Route a notification

        :param notification: A :class:`~autopush.endpoint.Notificaiton`
                             instance.
        :param uaid_data: A dict of the full user item from the db record.
        :returns: A response object upon successful routing.
        :rtype: :class:`RouterResponse`
        :raises: :exc:`RouterException` if routing fails.

        This function runs in the main reactor, if a yield is needed then a
        deferred must be returned for the callback chain.

        """
        raise NotImplementedError("route_notification must be implemented")
