"""HTTP Endpoint for Notifications

This is the primary running code of the ``autoendpoint`` script that handles
the reception of HTTP notification requests for AppServers.

"""
import hashlib
import json
import time
import urlparse
import uuid
from collections import namedtuple

import cyclone.web
from boto.dynamodb2.exceptions import (
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from cryptography.fernet import InvalidToken
from twisted.internet.defer import Deferred
from twisted.internet.threads import deferToThread
from twisted.python import failure, log

from autopush.router import available_routers
from autopush.router.interface import RouterException


class Notification(namedtuple("Notification", "version data channel_id")):
    """Parsed notification from the request"""


def parse_request_params(request):
    """Parse request params from either the body or query as needed and
    return them.

    :returns: Tuple of (version, data).

    """
    # If there's a request body, parse it out
    version = data = None
    if len(request.body) > 0:
        body_args = urlparse.parse_qs(request.body, keep_blank_values=True)
        version = body_args.get("version")
        data = body_args.get("data")
    else:
        version = request.arguments.get("version")
        data = request.arguments.get("data")

    # These come out as lists, unlist them
    if version is not None:
        try:
            version = int(version[0])
        except ValueError:
            version = None
    if data is not None:
        data = data[0]

    if version is None or version < 1:
        version = int(time.time())

    return version, data


class EndpointHandler(cyclone.web.RequestHandler):
    #############################################################
    #                    Cyclone API Methods
    #############################################################
    def initialize(self, ap_settings):
        """Setup basic aliases and attributes"""
        self.uaid_hash = ""
        self.ap_settings = ap_settings
        self.bridge = ap_settings.bridge
        self.metrics = ap_settings.metrics

    def prepare(self):
        """Common request preparation"""
        self._addCors()

    def write_error(self, code, **kwargs):
        """Write the error (otherwise unhandled exception when dealing with
        unknown method specifications.)

        This is a Cyclone API Override method.

        """
        self.set_status(code)
        if "exc_info" in kwargs:
            log.err(failure.Failure(*kwargs["exc_info"]),
                    **self._client_info())
        else:
            log.err("Error in handler: %s" % code, **self._client_info())
        self.finish()

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    def options(self, token):
        """HTTP OPTIONS Handler"""

    def head(self, token):
        """HTTP HEAD Handler"""

    @cyclone.web.asynchronous
    def put(self, token):
        """HTTP PUT Handler

        Primary entry-point to handling a notification for a push client.

        """
        self.start_time = time.time()
        fernet = self.ap_settings.fernet

        version, data = parse_request_params(self.request)
        if data and len(data) > self.ap_settings.max_data:
            self.set_status(401)
            log.msg("Data too large", **self._client_info())
            self.write("Data too large")
            return self.finish()

        d = deferToThread(fernet.decrypt, token.encode('utf8'))
        d.addCallback(self._token_valid, version, data)
        d.addErrback(self._token_err)
        d.addErrback(self._response_err)

    #############################################################
    #                    Callbacks
    #############################################################
    def _token_valid(self, result, version, data):
        self.uaid, chid = result.split(":")
        self.uaid_hash = hashlib.sha224(self.uaid).hexdigest()
        notification = Notification(version=version, data=data,
                                    channel_id=chid)
        d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
        d.addCallback(self._uaid_lookup_results, notification)
        d.addErrback(self._uaid_not_found_err)
        self._db_error_handling(d)

    def _uaid_lookup_results(self, result, notification):
        """Process the result of the AWS UAID lookup"""
        router_key = result.get("router", "internal_simplepush")
        router = available_routers[router_key]()
        router.initialize(self.ap_settings)
        d = Deferred()
        d.addCallback(router.route_notification)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        d.addCallback(self._router_completed, result)

        # Call the prepared router
        d.callback((notification, result))

    def _router_completed(self, response, uaid_data):
        # TODO: Add some custom wake logic here
        self.set_status(response.status_code)
        self.write(response.response_body)
        return self.finish()

    #############################################################
    #                    Utility Methods
    #############################################################
    def _client_info(self):
        """Returns a dict of additional client data"""
        return {
            "user-agent": self.request.headers.get("user-agent", ""),
            "remote-ip": self.request.headers.get("x-forwarded-for",
                                                  self.request.remote_ip),
            "uaid_hash": self.uaid_hash,
        }

    def _addCors(self):
        if self.ap_settings.cors:
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Methods", "PUT")

    def _db_error_handling(self, d):
        """Tack on the common error handling for a dynamodb request and
        uncaught exceptions"""
        d.addErrback(self._overload_err)
        d.addErrback(self._response_err)
        return d

    #############################################################
    #                    Error Callbacks
    #############################################################
    def _response_err(self, fail):
        """errBack for all exceptions that should be logged

        This traps all exceptions to prevent any further callbacks from
        running.

        """
        fail.trap(Exception)
        log.err(fail, **self._client_info())
        self.set_status(500)
        self.write("Error processing request")
        self.finish()

    def _overload_err(self, fail):
        """errBack for throughput provisioned exceptions"""
        fail.trap(ProvisionedThroughputExceededException)
        self.set_status(503)
        log.msg("Throughput Exceeded", **self._client_info())
        self.write("Server busy, try later")
        self.finish()

    def _token_err(self, fail):
        """errBack for token decryption fail"""
        fail.trap(InvalidToken)
        self.set_status(401)
        log.msg("Invalid token", **self._client_info())
        self.write("Invalid token")
        self.finish()

    def _uaid_not_found_err(self, fail):
        """errBack for uaid lookup not finding the user"""
        fail.trap(ItemNotFound)
        self.set_status(404)
        log.msg("UAID not found in AWS.", **self._client_info())
        self.write("Invalid")
        return self.finish()

    def _router_fail_err(self, fail):
        """errBack for router failures"""
        fail.trap(RouterException)
        log.err(fail, **self._client_info())
        exc = fail.value
        self.set_status(exc.status_code)
        self.write(exc.response_body)
        return self.finish()


class RegistrationHandler(cyclone.web.RequestHandler):
    def _client_info(self):
        """Returns a dict of additional client data"""
        return {
            "user-agent": self.request.headers.get("user-agent", ""),
            "remote-ip": self.request.headers.get("x-forwarded-for",
                                                  self.request.remote_ip),
            "uaid_hash": getattr(self, "uaid_hash", ""),
        }

    def _error_response(self, failure):
        log.err(failure, **self._client_info())
        self.set_status(500)
        self.write("Error processing request")
        self.finish()

    def _load_params(self):
        tags = {'chid': 'channelid',
                'conn': 'connect',
                }
        chid = conn = None
        if len(self.request.body) > 0:
            body = urlparse.parse_qs(self.request.body, keep_blank_values=True)
            chid = body.get(tags['chid'], [None])[0]
            conn = body.get(tags['conn'], [None])[0]
        if chid is None:
            chid = self.request.arguments.get(tags['chid'], [None])[0]
        if conn is None:
            conn = self.request.arguments.get(tags['conn'], [None])[0]

        if conn is None:
            log.msg("Missing %s %s" % (tags['conn'], conn))
            return False

        if chid is None or len(chid) == 0:
            chid = str(uuid.uuid4())

        self.chid = chid
        self.conn = conn
        return True

    def initialize(self):
        self.metrics = self.ap_settings.metrics

    def options(self, token):
        self._addCors()

    def head(self, token):
        self._addCors()

    def _addCors(self):
        if self.ap_settings.cors:
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Methods", "GET,PUT")

    def _error(self, code, msg):
        self.set_status(code, msg)
        self.finish()
        return

    @cyclone.web.asynchronous
    def get(self, uaid=None):
        if uaid is None:
            return self._error(400, "invalid UAID")
        try:
            uuid.UUID(uaid)
        except Exception, e:
            log.msg("Improper UAID value specified %s" % e)
            return self._error(400, "invalid UAID")
        self.uaid = uaid

        self.chid = str(uuid.uuid4())
        self._registered(True)

    @cyclone.web.asynchronous
    def put(self, uaid=None):
        self.metrics = self.ap_settings.metrics
        self.start_time = time.time()

        self.add_header("Content-Type", "application/json")

        if uaid is None:
            uaid = str(uuid.uuid4())
        else:
            try:
                uuid.UUID(uaid)
            except ValueError:
                log.msg("Invalid UAID [%s], swapping for valid one" % uaid,
                        **self._client_info())
                uaid = str(uuid.uuid4())

        self.uaid = uaid
        if not self._load_params():
            log.msg("Invalid parameters", **self._client_info())
            self.set_status(400, "Invalid arguments")
            self.finish()
            return
        d = deferToThread(self.bridge.register, self.uaid, self.conn)
        d.addCallback(self._registered)
        d.addErrback(self._error_response)

    def _registered(self, result):
        if not result:
            self.set_status(500, "Registration failure")
            log.err("Registration failure", **self._client_info())
            return self.finish()
        d = deferToThread(self.ap_settings.makeEndpoint,
                          self.uaid,
                          self.chid)
        d.addCallbacks(self._return_channel,
                       self._error_response)

    def _return_channel(self, endpoint):
        msg = {"useragentid": self.uaid,
               "channelid": self.chid,
               "endpoint": endpoint}
        self.set_status(200)
        self.write(json.dumps(msg))
        log.msg("Endpoint registered via HTTP", **self._client_info())
        return self.finish()
