"""Router interface"""
from autopush.exceptions import AutopushException


class RouterException(AutopushException):
    """Exception if routing has failed, may include a custom status_code and
    body to write to the response.

    """
    def __init__(self, message, status_code=500, response_body="",
                 router_data=None):
        super(AutopushException, self).__init__(message)
        self.status_code = status_code
        self.response_body = response_body or message


class RouterResponse(object):
    """Router response if routing has succeeded.

    If the router data needs to change as a result of this message, either the
    router got invalidated, or needs updating, then the router_data should be
    set.

    """
    def __init__(self, status_code=200, response_body="", router_data=None):
        self.status_code = status_code
        self.response_body = response_body
        self.router_data = router_data


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
