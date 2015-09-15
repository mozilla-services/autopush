"""HTTP Endpoints for Notifications

This is the primary running code of the ``autoendpoint`` script that handles
the reception of HTTP notification requests for AppServers.

Two HTTP endpoints are exposed by default:

1. :class:`EndpointHandler` - Handles Push notification deliveries from the
   :term:`AppServer`.
2. :class:`RegistrationHandler` - Handles Registration requests for registering
   additional router type/data when not using the default notification delivery
   scheme.

If no external routers are configured then the :class:`RegistrationHandler`
will not be able to perform any additional router data registration.

HTTP API
========

API methods requiring Authorization must include a HMAC, generated with SHA256
of the secret key sent on the original register ``POST`` and the message
payload being the raw content of the body (if any).

Hash: ``HMAC(key=secret, message=RAW_CONTENT_PAYLOAD)``

All message bodies must be UTF-8 encoded.

.. http:put:: /push/(uuid:token)

    Send a notification to the given endpoint `token`.

    If the client is using webpush style data delivery, then the body in its
    entirety will be regarded as the data payload for the message per
    `the WebPush spec
    <https://tools.ietf.org/html/draft-thomson-webpush-http2-02#section-5>`_.

    :form version: (*Optional*) Version of notification, defaults to current
                   time
    :statuscode 404: `token` is invalid.
    :statuscode 202: Message stored for delivery to client at a later
                     time.
    :statuscode 200: Message delivered to node client is connected to.

.. http:get:: /register/(uuid:uaid)

    Returns registered router data for the UAID.

    **Example Request**

    .. code-block:: http

        GET /register/5bbc4aae-a575-4f6a-a4b3-6f84a4d06a63
        Host: endpoint.push.com
        Authorization: HASH

    **Example Response**

    .. code-block:: http

        HTTP/1.1 200 OK
        Content-Type: application/json
        Content-Length: nnn

        {
            "type": "apns",
            "data": {
                "token": "APNS_TOKEN_DATA",
                ...
            }
        }

    :reqheader Authorization: Hash with message set to an empty string.

.. http:post:: /register/(uuid:uaid)

    Create a new endpoint for a given UAID, or register a new UAID and
    return a new endpoint.

    If a channelID is not supplied then one will be generated.

    **Endpoint w/New Registration**

    **Example Request (for APNS router)**:

    .. code-block:: http

        POST /register
        Host: endpoint.push.com
        Content-Type: application/json

        {
            "type": "apns",
            "channelID": "a13872c9-5cba-48ab-a8e5-955264647303",
            "data": {
                "token": "APNS_TOKEN_DATA",
                ...
            }
        }

    **Example Response**:

    .. code-block:: http

        HTTP/1.1 200 OK
        Content-Type: application/json
        Content-Length: nnn

        {
            "uaid": "5bbc4aae-a575-4f6a-a4b3-6f84a4d06a63",
            "secret": "4526e381eb6c191cf783da5d6df248e7",
            "channelID": "a13872c9-5cba-48ab-a8e5-955264647303",
            "endpoint": "https://endpoint.push.com/push/VERYLONGSTRING",
        }

    **Endpoint w/Existing UAID**

    **Example Request**:

    .. code-block:: http

        POST /register/5bbc4aae-a575-4f6a-a4b3-6f84a4d06a63
        Host: endpoint.push.com
        Authorization: HASH
        Content-Type: application/json

        {}

    **Example Response**:

    .. code-block:: http

        HTTP/1.1 200 OK
        Content-Type: application/json
        Content-Length: nnn

        {
            "channelID": "8a90e38a-f36c-4c77-901a-c11d02c1516f",
            "endpoint": "https://endpoint.push.com/push/VERYLONGSTRING",
        }

    :reqheader Authorization: Hash with message set to raw body content
                              required for existing UAID's.

.. http:put:: /register/(uuid:uaid)

    Update router data for an existing UAID.

    This endpoint handles updating the router data/type for an existing
    UAID and requires the nonce/hash for the UAID given.

    **Update Router Data**

    **Example Request**:

    .. code-block:: http

        PUT /register/5bbc4aae-a575-4f6a-a4b3-6f84a4d06a63
        Host: endpoint.push.com
        Authorization: HASH
        Content-Type: application/json

        {
            "type": "gcm",
            "data": {
                "token": "TOKEN_DATA_FOR_ROUTER_TYPE",
                ...
            }
        }

    **Example Response**:

    .. code-block:: http

        HTTP/1.1 200 OK
        Content-Type: application/json
        Content-Length: nnn

        {}

    :reqheader Authorization: Hash with message set to raw body content
                              required for existing UAID's.

"""
import hashlib
import json
import time
import urlparse
import uuid
from collections import namedtuple
from base64 import urlsafe_b64encode

import cyclone.web
from boto.dynamodb2.exceptions import (
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from cryptography.fernet import InvalidToken
from twisted.internet.defer import Deferred
from twisted.internet.threads import deferToThread
from twisted.python import failure, log

from autopush.router.interface import RouterException
from autopush.utils import (
    generate_hash,
    validate_hash,
)


class Notification(namedtuple("Notification",
                   "version data channel_id headers ttl")):
    """Parsed notification from the request"""


def parse_request_params(request):
    """Parse request params from either the body or query as needed and
    return them

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


class AutoendpointHandler(cyclone.web.RequestHandler):
    """Common overrides for Autoendpoint handlers"""
    cors_methods = ""
    cors_request_headers = []
    cors_response_headers = []

    #############################################################
    #                    Cyclone API Methods
    #############################################################
    def initialize(self, ap_settings):
        """Setup basic aliases and attributes"""
        self.uaid_hash = ""
        self._uaid = ""
        self.ap_settings = ap_settings
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
        self.uaid_hash = hashlib.sha224(self.uaid).hexdigest()

    def _client_info(self):
        """Returns a dict of additional client data"""
        return {
            "user-agent": self.request.headers.get("user-agent", ""),
            "remote-ip": self.request.headers.get("x-forwarded-for",
                                                  self.request.remote_ip),
            "uaid_hash": self.uaid_hash,
            "router_key": getattr(self, "router_key", ""),
            "channel_id": getattr(self, "chid", ""),
        }

    #############################################################
    #                    Error Callbacks
    #############################################################
    def _response_err(self, fail):
        """errBack for all exceptions that should be logged

        This traps all exceptions to prevent any further callbacks from
        running.

        """
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

    def _router_response(self, response):
        self.set_status(response.status_code)
        for name, val in response.headers.items():
            self.set_header(name, val)
        self.write(response.response_body)
        self.finish()

    def _router_fail_err(self, fail):
        """errBack for router failures"""
        fail.trap(RouterException)
        exc = fail.value
        if exc.log_exception:
            log.err(fail, **self._client_info())
        if 200 <= exc.status_code < 300:
            log.msg("Success", status_code=exc.status_code,
                    **self._client_info())
        self._router_response(exc)

    def _uaid_not_found_err(self, fail):
        """errBack for uaid lookup not finding the user"""
        fail.trap(ItemNotFound)
        self.set_status(404)
        log.msg("UAID not found in AWS.", **self._client_info())
        self.write("Invalid")
        return self.finish()

    def _token_err(self, fail):
        """errBack for token decryption fail"""
        fail.trap(InvalidToken, ValueError)
        self.set_status(404)
        log.msg("Invalid token", **self._client_info())
        self.write("Invalid token")
        self.finish()

    #############################################################
    #                    Utility Methods
    #############################################################
    def _db_error_handling(self, d):
        """Tack on the common error handling for a dynamodb request and
        uncaught exceptions"""
        d.addErrback(self._overload_err)
        d.addErrback(self._response_err)
        return d


class MessageHandler(AutoendpointHandler):
    cors_methods = "DELETE"

    @cyclone.web.asynchronous
    def delete(self, token):
        """Drops a pending message.

        The message will only be removed from DynamoDB. Messages that were
        successfully routed to a client as direct updates, but not delivered
        yet, will not be dropped.
        """
        self.version = token
        d = deferToThread(self.ap_settings.fernet.decrypt,
                          self.version.encode('utf8'))
        d.addCallback(self._token_valid)
        d.addErrback(self._token_err)
        d.addErrback(self._response_err)
        return d

    def _token_valid(self, result):
        info = result.split(":")
        if len(info) != 3:
            raise ValueError("Wrong message token components")

        kind, uaid, chid = info
        if kind != 'm':
            raise ValueError("Wrong message token kind")

        d = deferToThread(self.ap_settings.message.delete_message, uaid,
                          chid, self.version)
        d.addCallback(self._delete_completed)
        self._db_error_handling(d)
        d.addErrback(self._response_err)
        return d

    def _delete_completed(self, response):
        self.set_status(204)
        self.finish()


class EndpointHandler(AutoendpointHandler):
    cors_methods = "POST,PUT"
    cors_request_headers = ["content-encoding", "encryption",
                            "encryption-key", "content-type"]
    cors_response_headers = ["location"]

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    @cyclone.web.asynchronous
    def put(self, token):
        """HTTP PUT Handler

        Primary entry-point to handling a notification for a push client.

        """
        self.start_time = time.time()
        fernet = self.ap_settings.fernet

        d = deferToThread(fernet.decrypt, token.encode('utf8'))
        d.addCallback(self._token_valid)
        d.addErrback(self._token_err)
        d.addErrback(self._response_err)
    post = put

    #############################################################
    #                    Callbacks
    #############################################################
    def _token_valid(self, result):
        """Called after the token is decrypted successfully"""
        info = result.split(":")
        if len(info) != 2:
            raise ValueError("Wrong subscription token components")

        self.uaid, self.chid = info
        d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
        d.addCallback(self._uaid_lookup_results)
        d.addErrback(self._uaid_not_found_err)
        self._db_error_handling(d)

    def _uaid_lookup_results(self, result):
        """Process the result of the AWS UAID lookup"""
        # Save the whole record
        router_key = self.router_key = result.get("router_type", "simplepush")
        self.router = self.ap_settings.routers[router_key]

        # Only simplepush uses version/data out of body/query, GCM/APNS will
        # use data out of the request body 'WebPush' style.
        if router_key == "simplepush":
            version, data = parse_request_params(self.request)
        else:
            data = self.request.body
            if router_key == "webpush":
                # We need crypto headers for messages with payloads.
                req_fields = ["content-encoding", "encryption"]
                if data and not all([x in self.request.headers
                                     for x in req_fields]):
                    self.set_status(400)
                    log.msg("Missing Crypto headers", **self._client_info())
                    self.write("Missing crypto headers.")
                    return self.finish()

        try:
            ttl = int(self.request.headers.get("ttl", "0"))
        except ValueError:
            ttl = 0
        if data and len(data) > self.ap_settings.max_data:
            self.set_status(413)
            log.msg("Data too large", **self._client_info())
            self.write("Data too large")
            return self.finish()

        if router_key == "simplepush":
            self._route_notification(version, result, data)
            return

        # Web Push messages are encrypted binary blobs. We store and deliver
        # these messages as Base64-encoded strings.
        if router_key == "webpush":
            data = urlsafe_b64encode(self.request.body)

        d = deferToThread(self.ap_settings.fernet.encrypt, ':'.join([
            'm', self.uaid, self.chid]).encode('utf8'))
        d.addCallback(self._route_notification, result, data, ttl)
        return d

    def _route_notification(self, version, result, data, ttl=None):

        notification = Notification(version=version, data=data,
                                    channel_id=self.chid,
                                    headers=self.request.headers,
                                    ttl=ttl)

        d = Deferred()
        d.addCallback(self.router.route_notification, result)
        d.addCallback(self._router_completed, result)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)

        # Call the prepared router
        d.callback(notification)

    def _router_completed(self, response, uaid_data):
        """Called after router has completed successfully"""
        # TODO: Add some custom wake logic here

        # Were we told to update the router data?
        if response.router_data is not None:
            if not response.router_data:
                del uaid_data["router_data"]
                del uaid_data["router_type"]
            else:
                uaid_data["router_data"] = response.router_data
            uaid_data["connected_at"] = int(time.time() * 1000)
            d = deferToThread(self.ap_settings.router.register_user,
                              uaid_data)
            response.router_data = None
            d.addCallback(lambda x: self._router_completed(response,
                                                           uaid_data))
            return d
        else:
            if response.status_code == 200:
                log.msg("Successful delivery", **self._client_info())
            elif response.status_code == 202:
                log.msg("Router miss, message stored.", **self._client_info())
            time_diff = time.time() - self.start_time
            self.metrics.timing("updates.handled", duration=time_diff)
            self._router_response(response)


class RegistrationHandler(AutoendpointHandler):
    cors_methods = "GET,PUT"

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    @cyclone.web.asynchronous
    def get(self, uaid=""):
        """HTTP GET

        Retrieves the router type/data for a UAID.

        """
        if not self._validate_auth(uaid):
            return self._error(401, "Invalid Authentication")

        self.uaid = uaid
        self.chid = str(uuid.uuid4())
        d = deferToThread(self.ap_settings.router.get_uaid, uaid)
        d.addCallback(self._return_router_data)
        d.addErrback(self._overload_err)
        d.addErrback(self._uaid_not_found_err)
        d.addErrback(self._response_err)
        return d

    @cyclone.web.asynchronous
    def post(self, uaid=""):
        """HTTP POST

        Endpoint generation and optionally router type/data registration.

        """
        self.start_time = time.time()
        self.add_header("Content-Type", "application/json")
        params = self._load_params()
        if "channelID" not in params:
            return self._error(400, "Invalid arguments")

        # If there's a UAID, ensure its valid, otherwise we ensure the hash
        # matches up
        new_uaid = False
        if uaid:
            if not self._validate_auth(uaid):
                return self._error(401, "Invalid Authentication")
        else:
            # No UAID supplied, make our own
            uaid = str(uuid.uuid4())
            new_uaid = True
        self.uaid = uaid
        router_type = params.get("type")
        if new_uaid and router_type not in self.ap_settings.routers:
            log.msg("Invalid parameters", **self._client_info())
            return self._error(400, "Invalid arguments")
        self.chid = params["channelID"]
        if new_uaid:
            router = self.ap_settings.routers[router_type]
            d = Deferred()
            d.addCallback(router.register, params.get("data", {}))
            d.addCallback(self._save_router_data, router_type)
            d.addCallback(self._make_endpoint)
            d.addCallback(self._return_endpoint, new_uaid)
            d.addErrback(self._router_fail_err)
            d.addErrback(self._response_err)
            d.callback(uaid)
        else:
            d = self._make_endpoint(None)
            d.addCallback(self._return_endpoint, new_uaid)
            d.addErrback(self._response_err)

    @cyclone.web.asynchronous
    def put(self, uaid=""):
        """HTTP PUT

        Update router type/data for a UAID.

        """
        self.start_time = time.time()

        if not self._validate_auth(uaid):
            return self._error(401, "Invalid Authentication")

        params = self._load_params()
        self.uaid = uaid
        router_type = params.get("type")
        router_data = params.get("data")
        if router_type not in self.ap_settings.routers or not router_data:
            log.msg("Invalid parameters", **self._client_info())
            return self._error(400, "Invalid arguments")

        self.add_header("Content-Type", "application/json")
        router = self.ap_settings.routers[router_type]

        d = Deferred()
        d.addCallback(router.register, router_data)
        d.addCallback(self._save_router_data, router_type)
        d.addCallback(self._success)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        d.callback(uaid)

    #############################################################
    #                    Callbacks
    #############################################################
    def _return_router_data(self, user_item):
        """Called after UAID data is retrieved"""
        msg = dict(
            type=user_item["router_type"],
            data=user_item["router_data"],
        )
        self.write(json.dumps(msg))
        self.finish()

    def _save_router_data(self, router_data, router_type):
        """Called when new data needs to be saved to a user-record"""
        user_item = dict(
            uaid=self.uaid,
            router_type=router_type,
            router_data=router_data,
            connected_at=int(time.time() * 1000),
        )
        return deferToThread(self.ap_settings.router.register_user, user_item)

    def _make_endpoint(self, result):
        """Called to create a new endpoint"""
        return deferToThread(self.ap_settings.make_endpoint,
                             self.uaid, self.chid)

    def _return_endpoint(self, endpoint, new_uaid):
        """Called after the endpoint was made and should be returned to the
        requestor"""
        if new_uaid:
            hashed = generate_hash(self.uaid, self.ap_settings.crypto_key)
            msg = dict(
                uaid=self.uaid,
                secret=hashed,
                channelID=self.chid,
                endpoint=endpoint,
            )
        else:
            msg = dict(channelID=self.chid, endpoint=endpoint)
        self.write(json.dumps(msg))
        log.msg("Endpoint registered via HTTP", **self._client_info())
        self.finish()

    def _success(self, result):
        """Writes out empty 200 response"""
        self.write({})
        self.finish()

    #############################################################
    #                    Utility Methods
    #############################################################
    def _validate_auth(self, uaid):
        """Validates the Authorization header in a request"""
        secret = self.ap_settings.crypto_key
        hashed = self.request.headers.get("Authorization", "").strip()
        key = generate_hash(secret, uaid)
        return validate_hash(key, self.request.body, hashed)

    def _error(self, code, msg):
        """Writes out an error status code"""
        self.set_status(code, msg)
        self.finish()

    def _load_params(self):
        """Load and parse a JSON body out of the request body, or return an
        empty dict"""
        try:
            return json.loads(self.request.body)
        except ValueError:
            return {}
