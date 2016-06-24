"""Validation handler and Schemas"""
import time
import urlparse
from functools import wraps

from boto.dynamodb2.exceptions import (
    ItemNotFound,
)
from marshmallow import (
    Schema,
    fields,
    pre_load,
    validates,
    validates_schema,
)
from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
)


class ThreadedValidate(object):
    """A cyclone request validation decorator

    Exposed as a classmethod for running a marshmallow-based validation schema
    in a separate thread for a cyclone request handler.

    """
    log = Logger()

    def __init__(self, schema):
        self.schema = schema

    def _validate_request(self, request_handler):
        """Validates a schema_class against a cyclone request"""
        data = {
            "headers": request_handler.request.headers,
            "body": request_handler.request.body,
            "path_args": request_handler.path_args,
            "path_kwargs": request_handler.path_kwargs,
            "arguments": request_handler.request.arguments,
        }
        self.schema.context["settings"] = request_handler.ap_settings
        self.schema.context["log"] = self.log
        return self.schema.load(data)

    def _call_func(self, result, func, request_handler, *args, **kwargs):
        output, errors = result
        if errors:
            return request_handler._write_validation_err(errors)
        request_handler.valid_input = output
        return func(request_handler, *args, **kwargs)

    def _decorator(self, func):
        @wraps(func)
        def wrapper(request_handler, *args, **kwargs):
            # Wrap the handler in @cyclone.web.synchronous
            request_handler._auto_finish = False

            d = deferToThread(self._validate_request, request_handler)
            d.addErrback(request_handler._overload_err)
            d.addErrback(request_handler._validation_err)
            d.addErrback(request_handler._response_err)
            d.addCallback(self._call_func, func, request_handler, *args,
                          **kwargs)
        return wrapper

    @classmethod
    def validate(cls, schema):
        """Validate a request schema in a separate thread before calling the
        request handler

        An alias `threaded_validate` should be used from this module.

        Using `cyclone.web.asynchronous` is not needed as this function
        will attach equivilant functionality to the method handler. Calling
        `self.finish()` is needed on decorated handlers.

        .. code-block::

            class MyHandler(cyclone.web.RequestHandler):
                @threaded_validate(MySchema())
                def post(self):
                    ...

        """
        return cls(schema)._decorator


# Alias to the validation classmethod decorator
threaded_validate = ThreadedValidate.validate


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
        version = data = None
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
