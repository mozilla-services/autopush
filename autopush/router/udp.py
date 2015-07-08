"""UDP Router"""
import json

import requests

from twisted.python import log
from twisted.internet.threads import deferToThread

from autopush.router.interface import RouterException, RouterResponse


class UDPRouter(object):
    """UDP Router Implementation"""
    wake_host = {}
    mobile_net = {}

    def __init__(self, ap_settings, router_conf):
        """Create a new UDP router and connect to UDP"""
        self.config = router_conf

    def register(self, uaid, router_data):
        """Validate that a token is in the ``router_data``"""
        if not router_data.get("wakeup_hostport"):
            self._error("connect info missing 'wakeup_hostport'", status=401)
        self.wake_host = router_data.get("wakeup_hostport")
        if not router_data.get("mobilenetwork"):
            self._error("connect info missing 'mobilenetwork'", status=401)
        self.mobile_net = router_data.get("mobilenetwork")
        return router_data

    def route_notification(self, notification, uaid_data):
        """Start the UDP notification routing, returns a deferred"""
        router_data = uaid_data["router_data"]
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, router_data)

    def _route(self, notification, router_data):
        """Route the message to the disconnected endpoint."""
        payload = json.dumps(self.mobile_net)
        host = router_data.get("wakeup_hostport", {}).get("ip", "")
        if host == "":
            return
        port = router_data.get("wakeup_hostport", {}).get("port", None)
        if port is not None:
            host = host + ":" + port
        try:
            response = requests.post(
                "https://" + host,
                data=payload,
                cert=self.config.get("pem_file")
            )
            if response.status_code >= 200 or response.status_code < 300:
                return RouterResponse(
                    status_code=response.status_code,
                    response_body="Message sent")
        except Exception, e:
            self._error("Unhandled exception in UDP Routing: %s" % e, 500)
        return RouterResponse(
            status_code=500,
            response_body="Please try request later")

    def _error(self, err, status, **kwargs):
        """Error handler that raises the RouterException"""
        log.err(err, **kwargs)
        raise RouterException(err, status_code=status, response_body=err)
