"""Router interface"""
from typing import Any  # noqa

from autopush.types import JSONDict  # noqa


class RouterResponse(object):
    """Router response if routing has succeeded.

    If the router data needs to change as a result of this message, either the
    router got invalidated, or needs updating, then the router_data should be
    set.

    """
    def __init__(self, status_code=200, response_body="", router_data=None,
                 headers=None, errno=None, logged_status=None):
        """Create a new RouterResponse"""
        self.status_code = status_code
        self.response_body = response_body
        self.router_data = router_data
        self.headers = {} if headers is None else headers
        self.errno = errno
        self.logged_status = logged_status


class IRouter(object):
    def __init__(self, conf, router_conf, **kwargs):
        """Initialize the Router to handle notifications and registrations with
        the given conf and router conf."""
        raise NotImplementedError("__init__ must be implemented")

    def register(self, uaid, router_data, app_id, *args, **kwargs):
        # type: (str, JSONDict, str, *Any, **Any) -> None
        """Register the uaid with router_data however is preferred prior to
        storing router_data for this user.

        :param uaid: User Agent Identifier
        :param router_data: Route specific configuration info
        :param app_id: Application identifier from URI

        :raises:
            :exc:`RouterException` if data supplied is invalid.

        """
        raise NotImplementedError("register must be implemented")

    def amend_endpoint_response(self, response, router_data):
        # type: (JSONDict, JSONDict) -> None
        """Modify an outbound Endpoint registration response to
        include router info.

        Some routers require additional info to be returned to
        clients.

        :param response: The response data to be sent to the client
        :param router_data: Route specific configuration info

        """
        raise NotImplementedError(
            "amend_endpoint_response must be implemented")

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
