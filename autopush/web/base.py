import json
import time
from collections import namedtuple

from boto.dynamodb2.exceptions import (
    ProvisionedThroughputExceededException,
)
from boto.exception import BotoServerError

from autopush.base import BaseHandler
from autopush.db import (
    hasher,
    normalize_id,
)
from autopush.exceptions import InvalidRequest
from autopush.router.interface import RouterException

status_codes = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    413: "Payload Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}

DEFAULT_ERR_URL = ("http://autopush.readthedocs.io/en/latest/http.html"
                   "#error-codes")


class Notification(namedtuple("Notification",
                   "version data channel_id headers ttl")):
    """Parsed notification from the request"""


class VapidAuthException(Exception):
    """Exception if the VAPID Auth token fails"""


class BaseWebHandler(BaseHandler):
    """Common overrides for Push web API's"""
    cors_methods = ""
    cors_request_headers = ()
    cors_response_headers = ()

    #############################################################
    #                    Cyclone API Methods
    #############################################################
    def initialize(self, ap_settings):
        """Setup basic aliases and attributes"""
        super(BaseWebHandler, self).initialize(ap_settings)
        self.uaid_hash = self._uaid = self._chid = ""
        self.start_time = time.time()
        self.metrics = ap_settings.metrics

    def prepare(self):
        """Common request preparation"""
        if self.ap_settings.cors:
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Methods",
                            self.cors_methods)
            self.set_header("Access-Control-Allow-Headers",
                            ",".join(self.cors_request_headers))
            self.set_header("Access-Control-Expose-Headers",
                            ",".join(self.cors_response_headers))

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    def options(self, *args, **kwargs):
        """HTTP OPTIONS Handler"""

    def head(self, *args, **kwargs):
        """HTTP HEAD Handler"""

    #############################################################
    #                    Utility Methods
    #############################################################
    @property
    def uaid(self):
        """Return the UAID that was set"""
        return self._uaid

    @uaid.setter
    def uaid(self, value):
        """Set the UAID and update the uaid hash"""
        self._uaid = value
        self.uaid_hash = hasher(value)
        self._client_info["uaid_hash"] = self.uaid_hash

    @property
    def chid(self):
        """Return the ChannelID"""
        return self._chid

    @chid.setter
    def chid(self, value):
        """Set the ChannelID and record to _client_info"""
        self._chid = normalize_id(value)
        self._client_info["channelID"] = self._chid

    #############################################################
    #                    Error Callbacks
    #############################################################
    def _write_response(self, status_code, errno, message=None, headers=None,
                        url=DEFAULT_ERR_URL):
        """Writes out a full JSON error and sets the appropriate status"""
        self.set_status(status_code)
        error_data = dict(
            code=status_code,
            errno=errno,
            error=status_codes.get(status_code, ""),
            more_info=url,
        )
        if message:
            error_data["message"] = message
        self.write(json.dumps(error_data))
        self.set_header("Content-Type", "application/json")
        if headers:
            for header in headers.keys():
                self.set_header(header, headers.get(header))
        self.finish()

    def _validation_err(self, fail):
        """errBack for validation errors"""
        fail.trap(InvalidRequest)
        exc = fail.value
        self.log.info(format="Request validation error",
                      status_code=exc.status_code,
                      errno=exc.errno)
        self._write_response(exc.status_code, exc.errno,
                             message="Request did not validate %s" %
                                     (exc.message or ""),
                             headers=exc.headers)

    def _response_err(self, fail):
        """errBack for all exceptions that should be logged

        This traps all exceptions to prevent any further callbacks from
        running.

        """
        fmt = fail.value.message or 'Exception'
        self.log.failure(format=fmt, failure=fail,
                         status_code=500, errno=999, **self._client_info)
        self._write_response(500, 999, message="An unexpected server error"
                                               " occurred.")

    def _overload_err(self, fail):
        """errBack for throughput provisioned exceptions"""
        fail.trap(ProvisionedThroughputExceededException)
        self.log.info(format="Throughput Exceeded", status_code=503,
                      errno=201, **self._client_info)
        self._write_response(503, 201,
                             message="Please slow message send rate")

    def _boto_err(self, fail):
        """errBack for random boto exceptions"""
        fail.trap(BotoServerError)
        self.log.info(format="BOTO Error: %s" % str(fail.value),
                      status_code=503, errno=202, **self._client_info)
        self._write_response(503, errno=202,
                             message="Communication error, please retry")

    def _router_response(self, response):
        for name, val in response.headers.items():
            self.set_header(name, val)

        if 200 <= response.status_code < 300:
            self.set_status(response.status_code)
            self.write(response.response_body)
            self.finish()
        else:
            self._write_response(
                response.status_code,
                errno=response.errno or 999,
                message=response.response_body)

    def _router_fail_err(self, fail):
        """errBack for router failures"""
        fail.trap(RouterException)
        exc = fail.value
        if exc.log_exception or exc.status_code >= 500:
            fmt = fail.value.message or 'Exception'
            self.log.failure(format=fmt,
                             failure=fail, status_code=exc.status_code,
                             errno=exc.errno or "",
                             **self._client_info)  # pragma nocover
        if 200 <= exc.status_code < 300:
            self.log.info(format="Success", status_code=exc.status_code,
                          logged_status=exc.logged_status or "",
                          **self._client_info)
        elif 400 <= exc.status_code < 500:
            self.log.info(format="Client error",
                          status_code=exc.status_code,
                          logged_status=exc.logged_status or "",
                          errno=exc.errno or "",
                          **self._client_info)
        self._router_response(exc)

    def _write_validation_err(self, errors):
        """Writes a set of validation errors out with details about what
        went wrong"""
        self.set_status(400)
        error_data = dict(
            code=400,
            errors=errors
        )
        self.write(json.dumps(error_data))
        self.finish()
