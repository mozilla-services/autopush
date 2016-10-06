import time

from twisted.internet.defer import Deferred

from autopush.db import hasher
from autopush.web.base import (
    threaded_validate,
    Notification,
    BaseWebHandler,
)
from autopush.web.push_validation import SimplePushRequestSchema


class SimplePushHandler(BaseWebHandler):
    cors_methods = "PUT"

    @threaded_validate(SimplePushRequestSchema)
    def put(self, api_ver="v1", token=None):
        sub = self.valid_input["subscription"]
        user_data = sub["user_data"]
        router = self.ap_settings.routers[user_data["router_type"]]
        self._client_info["uaid"] = hasher(user_data.get("uaid"))
        self._client_info["channel_id"] = user_data.get("chid")
        self._client_info["message_id"] = self.valid_input["version"]

        notification = Notification(
            version=self.valid_input["version"],
            data=self.valid_input["data"],
            channel_id=str(sub["chid"]),
        )

        d = Deferred()
        d.addCallback(router.route_notification, user_data)
        d.addCallback(self._router_completed, user_data, "")
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)

        # Call the prepared router
        d.callback(notification)

    def _router_completed(self, response, uaid_data, warning=""):
        """Called after router has completed successfully"""
        if response.status_code == 200 or response.logged_status == 200:
            self.log.info(format="Successful delivery",
                          client_info=self._client_info)
        elif response.status_code == 202 or response.logged_status == 202:
            self.log.info(format="Router miss, message stored.",
                          client_info=self._client_info)
        time_diff = time.time() - self.start_time
        self.metrics.timing("updates.handled", duration=time_diff)
        response.response_body = (
            response.response_body + " " + warning).strip()
        self._router_response(response)
