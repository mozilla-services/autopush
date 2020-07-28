import json
import time
from functools import wraps

from botocore.exceptions import ClientError
from marshmallow.schema import UnmarshalResult  # noqa
from typing import (  # noqa
    Any,
    Callable,
    Sequence
)
from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from autopush.base import BaseHandler
from autopush.exceptions import InvalidRequest, RouterException

status_codes = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    413: "Payload Too Large",
    418: "I'm a teapot",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
# Older versions used "bearer", newer specification requires "webpush"
AUTH_SCHEMES = ["bearer", "webpush", "vapid"]
PREF_SCHEME = "webpush"
DEFAULT_ERR_URL = ("http://autopush.readthedocs.io/en/latest/http.html"
                   "#error-codes")


class ThreadedValidate(object):
    """A cyclone request validation decorator

    Exposed as a classmethod for running a marshmallow-based validation schema
    in a separate thread for a cyclone request handler.

    """
    log = Logger()

    def __init__(self, schema):
        self.schema = schema

    def _validate_request(self, request_handler, *args, **kwargs):
        # type: (BaseWebHandler, *Any, **Any) -> UnmarshalResult
        """Validates a schema_class against a cyclone request"""
        data = {
            "headers": request_handler.request.headers,
            "body": request_handler.request.body,
            "path_args": args,
            "path_kwargs": kwargs,
            "arguments": request_handler.request.arguments,
        }
        schema = self.schema()
        schema.context.update(
            conf=request_handler.conf,
            metrics=request_handler.metrics,
            db=request_handler.db,
            routers=request_handler.routers,
            log=self.log
        )
        return schema.load(data)

    def _call_func(self, result, func, request_handler):
        # type: (UnmarshalResult, Callable, BaseWebHandler) -> Any
        output_kwargs, errors = result
        if errors:
            request_handler._write_validation_err(errors)
        else:
            return func(request_handler, **output_kwargs)

    def _track_validation_timing(self, result, request_handler, start_time):
        # type: (Any, BaseWebHandler, float) -> Any
        """Track the validation timing"""
        request_handler._timings["validation_time"] = time.time() - start_time
        return result

    def _decorator(self, func):
        @wraps(func)
        def wrapper(request_handler, *args, **kwargs):
            start_time = time.time()
            # Wrap the handler in @cyclone.web.synchronous
            request_handler._auto_finish = False
            d = deferToThread(
                self._validate_request, request_handler, *args, **kwargs)
            d.addBoth(self._track_validation_timing, request_handler,
                      start_time)
            d.addCallback(self._call_func, func, request_handler)
            # Errbacks for _validate_request: handler functions should
            # explicitly manage their own Errbacks
            d.addErrback(request_handler._boto_err)
            d.addErrback(request_handler._validation_err)
            d.addErrback(request_handler._response_err)
        return wrapper

    @classmethod
    def validate(cls, schema):
        """Validate a request schema in a separate thread before calling the
        request handler

        An alias `threaded_validate` should be used from this module.

        Using `cyclone.web.asynchronous` is not needed as this function
        will attach equivilant functionality to the method handler. Calling
        `self.finish()` is needed on decorated handlers.

        Validated requests are deserialized into the `**kwargs` of the wrapped
        request handler method.

        .. code-block:: python

            class MySchema(Schema):
                uaid = fields.UUID(allow_none=True)

            class MyHandler(cyclone.web.RequestHandler):
                @threaded_validate(MySchema())
                def post(self, uaid=None):
                    ...

        """
        return cls(schema)._decorator


# Alias to the validation classmethod decorator
threaded_validate = ThreadedValidate.validate


class NotFoundHandler(BaseHandler):
    def get(self, *args, **kwargs):
        status_code = 404
        error = "Page not found"
        self.set_status(status_code, reason=error)
        error_data = dict(
            code=status_code,
            error=error or status_codes.get(status_code, ""),
        )
        self.write(json.dumps(error_data))
        self.set_header("Content-Type", "application/json")
        self.set_header("Strict-Transport-Security", "max-age=31536000")
        self.finish()
    put = post = delete = get


class BaseWebHandler(BaseHandler):
    """Common overrides for Push web API's"""
    cors_methods = ""
    cors_request_headers = ()   # type: Sequence[str]
    cors_response_headers = ()  # type: Sequence[str]

    #############################################################
    #                    Cyclone API Methods
    #############################################################
    def initialize(self):
        """Setup basic aliases and attributes"""
        super(BaseWebHandler, self).initialize()
        self._base_tags = {}
        self._start_time = time.time()
        self._timings = {}
        self._handling_message = False

    @property
    def routers(self):
        return self.application.routers

    def prepare(self):
        """Common request preparation"""
        if self.conf.enable_tls_auth:
            self.authenticate_peer_cert()
        if self.conf.cors:
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Methods",
                            self.cors_methods)
            self.set_header("Access-Control-Allow-Headers",
                            ",".join(self.cors_request_headers))
            self.set_header("Access-Control-Expose-Headers",
                            ",".join(self.cors_response_headers))
        if self.conf.sts_max_age:
            self.set_header("Strict-Transport-Security",
                            ";".join([
                                "max-age={}".format(self.conf.sts_max_age),
                                "includeSubDomains"
                                ]))

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    def options(self, *args, **kwargs):
        """HTTP OPTIONS Handler"""

    def head(self, *args, **kwargs):
        """HTTP HEAD Handler"""

    #############################################################
    #                    Error Callbacks
    #############################################################
    def _write_response(self, status_code, errno, message=None, error=None,
                        headers=None,
                        url=DEFAULT_ERR_URL,
                        router_type=None,
                        vapid=None):
        """Writes out a full JSON error and sets the appropriate status"""
        self.set_status(status_code, reason=error)
        error_data = dict(
            code=status_code,
            errno=errno,
            error=error or status_codes.get(status_code, ""),
            more_info=url,
        )
        if message:
            error_data["message"] = message
        self.write(json.dumps(error_data))
        self.set_header("Content-Type", "application/json")
        if headers:
            for header in headers.keys():
                self.set_header(header, headers.get(header))

        # 410's get the max-age cache control header
        if status_code == 410:
            self.set_header("Cache-Control", "max-age=86400")

        if self._handling_message and status_code >= 300:
            self.metrics.increment('notification.message.error',
                                   tags=[
                                       "code:{}".format(status_code),
                                       "router:{}".format(router_type),
                                       "vapid:{}".format(vapid is not None)
                                   ])
        self._track_timing()
        self.finish()

    def _validation_err(self, fail):
        """errBack for validation errors"""
        fail.trap(InvalidRequest)
        exc = fail.value
        self.log.debug(format="Request validation error: {}".format(exc),
                       status_code=exc.status_code,
                       errno=exc.errno,
                       client_info=self._client_info)

        self._write_response(exc.status_code, exc.errno,
                             message="Request did not validate %s" %
                                     (str(exc) or ""),
                             headers=exc.headers)

    def _response_err(self, fail):
        """errBack for all exceptions that should be logged

        This traps all exceptions to prevent any further callbacks from
        running.

        """
        from twisted.internet.error import ConnectionDone
        fmt = str(fail.value) or 'Exception'
        if isinstance(fail.value, ConnectionDone):
            return
        self.log.failure(format=fmt, failure=fail,
                         status_code=500, errno=999,
                         client_info=self._client_info)
        self._write_response(500, 999, message="An unexpected server error"
                                               " occurred.")

    def _boto_err(self, fail):
        """errBack for boto exceptions (ClientError)"""
        fail.trap(ClientError)
        if (fail.value.response['Error']['Code'] ==
                "ProvisionedThroughputExceededException"):
            self.log.debug(format="Throughput Exceeded", status_code=503,
                           errno=201, client_info=self._client_info)
            self._write_response(503, 201,
                                 message="Please slow message send rate")
            return
        self.log.debug(format="Unhandled Client Error: {}".format(
            json.dumps(fail.value.response)), status_code=503, errno=202,
            client_info=self._client_info)
        self._write_response(503, 202, message="Unexpected Error")

    def _router_response(self, response, router_type, vapid):
        for name, val in response.headers.items():
            if val is not None:
                self.set_header(name, val)
        if 200 <= response.status_code < 300:
            self.set_status(response.status_code, reason=None)
            self.write(response.response_body)

            dest = 'Direct'
            if response.status_code == 202 or response.logged_status == 202:
                dest = 'Stored'

            if self._handling_message:
                self.metrics.increment('notification.message.success',
                                       tags=[
                                           'destination:{}'.format(dest),
                                           'router:{}'.format(router_type),
                                           'vapid:{}'.format(vapid is not None)
                                       ])
            self._track_timing(status_code=response.logged_status)
            self.finish()
        else:
            self._write_response(
                response.status_code,
                errno=response.errno or 999,
                message=response.response_body,
                router_type=router_type,
                vapid=vapid
            )

    def _router_fail_err(self, fail, router_type=None, vapid=False, uaid=None):
        """errBack for router failures"""
        fail.trap(RouterException)
        exc = fail.value
        if exc.log_exception:
            if exc.status_code >= 500:
                fmt = str(fail.value) or 'Exception'
                self.log.failure(
                    format=fmt,
                    failure=fail, status_code=exc.status_code,
                    errno=exc.errno or 0,
                    client_info=self._client_info)  # pragma nocover
            if 200 <= exc.status_code < 300:
                self.log.debug(format="Success", status_code=exc.status_code,
                               logged_status=exc.logged_status or 0,
                               client_info=self._client_info)
            elif 400 <= exc.status_code < 500:
                self.log.debug(format="Client error: {}".format(str(exc)),
                               status_code=exc.status_code,
                               logged_status=exc.logged_status or 0,
                               errno=exc.errno or 0,
                               client_info=self._client_info)
        # probably an overabundance of caution, but only drop users if
        # reporting a not found and they're mobile.
        if exc.status_code in [404, 410] and router_type in [
                'apns', 'fcm', 'adm']:
            tags = self._base_tags.update({
                "platform": router_type,
                "reason": "unregistered",
            })
            self.metrics.increment(
                    "notification.bridge.error",
                    tags=tags)

            self.db.router.drop_user(uaid)
        self._router_response(exc, router_type, vapid)

    def _write_validation_err(self, errors):
        """Writes a set of validation errors out with details about what
        went wrong"""
        self.set_status(400, reason=None)
        error_data = dict(
            code=400,
            errors=errors
        )
        self.write(json.dumps(error_data))
        self._track_timing()
        self.finish()

    def _db_error_handling(self, d):
        """Tack on the common error handling for a dynamodb request and
        uncaught exceptions"""
        d.addErrback(self._boto_err)
        d.addErrback(self._response_err)
        return d

    #############################################################
    #                    Utility Methods
    #############################################################
    def _track_timing(self, status_code=None):
        """Logs out the request timing tracking stats

        Note: The status code should be set before calling this function or
        passed in.

        """
        status_code = status_code or self.get_status()
        self._timings["request_time"] = time.time() - self._start_time
        self.log.debug("Request timings", client_info=self._client_info,
                       timings=self._timings, status_code=status_code)
