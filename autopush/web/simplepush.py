import time
import urlparse

from boto.dynamodb2.exceptions import ItemNotFound
from marshmallow import (
    Schema,
    fields,
    pre_load,
    validates,
    validates_schema,
)
from twisted.internet.defer import Deferred

from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
)

from autopush.db import hasher
from autopush.web.base import (
    threaded_validate,
    Notification,
    BaseWebHandler,
)


class SimplePushSubscriptionSchema(Schema):
    uaid = fields.UUID(required=True)
    chid = fields.UUID(required=True)

    @pre_load
    def extract_subscription(self, d):
        try:
            result = self.context["settings"].parse_endpoint(
                token=d["token"],
                version=d["api_ver"],
            )
        except InvalidTokenException:
            raise InvalidRequest("invalid token", errno=102)
        return result

    @validates_schema
    def validate_uaid_chid(self, d):
        try:
            result = self.context["settings"].router.get_uaid(d["uaid"].hex)
        except ItemNotFound:
            raise InvalidRequest("UAID not found", status_code=410, errno=103)

        if result.get("router_type") != "simplepush":
            raise InvalidRequest("Wrong URL for user", errno=108)

        # Propagate the looked up user data back out
        d["user_data"] = result


class SimplePushRequestSchema(Schema):
    subscription = fields.Nested(SimplePushSubscriptionSchema,
                                 load_from="token_info")
    version = fields.Integer(missing=time.time)
    data = fields.String(missing=None)

    @validates('data')
    def validate_data(self, value):
        max_data = self.context["settings"].max_data
        if value and len(value) > max_data:
            raise InvalidRequest(
                "Data payload must be smaller than {}".format(max_data),
                errno=104,
            )

    @pre_load
    def token_prep(self, d):
        d["token_info"] = dict(
            api_ver=d["path_kwargs"].get("api_ver"),
            token=d["path_kwargs"].get("token"),
        )
        return d

    @pre_load
    def extract_fields(self, d):
        body_string = d["body"]
        if len(body_string) > 0:
            body_args = urlparse.parse_qs(body_string, keep_blank_values=True)
            version = body_args.get("version")
            data = body_args.get("data")
        else:
            version = d["arguments"].get("version")
            data = d["arguments"].get("data")
        version = version[0] if version is not None else version
        data = data[0] if data is not None else data
        if version and version >= "1":
            d["version"] = version
        if data:
            d["data"] = data
        return d


class SimplePushHandler(BaseWebHandler):
    cors_methods = "PUT"

    @threaded_validate(SimplePushRequestSchema)
    def put(self, *args, **kwargs):
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
