"""HTTP Endpoints for Notifications

This is the primary running code of the `autoendpoint` script that handles
the reception of HTTP notification requests for AppServers.

Three HTTP endpoints are exposed by default:

1. :class:`EndpointHandler` - Handles Push notification deliveries from the
   :term:`AppServer`.
2. :class:`RegistrationHandler` - Handles Registration requests for registering
   additional router type/data when not using the default notification delivery
   scheme.
3. :class:`MessageHandler` - Handles individual message operations such as
   deleting a message before delivery, or updating the contents/ttl of an
   existing message pending delivery.

If no external routers are configured then the :class:`RegistrationHandler`
will not be able to perform any additional router data registration.

Push Service HTTP API
=====================

The following section describes how remote servers can send Push
Notifications to apps running on remote User Agents.

API methods requiring Authorization must provide the Authorization
header containing the authrorization token. The Authorization token is returned
as "secret" in the registration response.

Lexicon
-------

   :{UAID}: The Push User Agent Registration ID

Push assigns each remote recipient a unique identifier. This value is
assigned during **Registration**

   :{CHID}: The Channel Subscription ID

Push assigns a unique identifier for each subscription for a given {UAID}.
This value is assigned during **Channel Subscription**

   :{message-id}: The unique Message ID

Push assigns each message for a given Channel Subscription a unique
identifier. This value is assigned during **Send Notification**

Response
--------

The responses will be JSON formatted objects. In addition, API calls
will return valid HTTP error codes (see *Errors* sub-section for
descriptions of specific errors).

For non-success responses, an extended error code object will be
returned with the following format:

.. code-block:: json

    {
        "code": 404,  // matches the HTTP status code
        "errno": 103, // stable application-level error number
        "error": "Not Found", // string representation of the status
        "message": "No message found" // optional additional error information
    }

Unless otherwise specified, all calls return the following error codes:

-  20x - Success
-  301 - Moved + `Location:` if `{token}` is invalid (Bridge API Only)
-  400 - Bad Parameters

   - errno 101 - Missing neccessary crypto keys
   - errno 108 - Router type is invalid

-  401 - Bad Authorization

   - errno 109 - Invalid authentication

-  404 - `{UAID}` not found or invalid

   - errno 102 - Invalid URL endpoint
   - errno 103 - Expired URL endpoint
   - errno 105 - Endpoint became unavailable during request
   - errno 106 - Invalid subscription
   - errno 107 - Message not found

-  500 - Unknown server error

   - errno 999 - Unknown error

-  503 - Server temporarily unavaliable.

   -  errno 201 - Use exponential back-off for retries
   -  errno 202 - Immediate retry ok

Calls
-----

Send Notification
~~~~~~~~~~~~~~~~~

Send a notification to the given endpoint identified by it's `token`.

Call:
^^^^^
.. http:put:: /push/{token}

    If the client is using webpush style data delivery, then the body in its
    entirety will be regarded as the data payload for the message per
    `the WebPush spec
    <https://tools.ietf.org/html/draft-thomson-webpush-http2-02#section-5>`_.

Parameters:
^^^^^^^^^^^

    :form version: (*Optional*) Version of notification, defaults to current
                   time

Reply:
^^^^^^

.. code-block:: json

    {"message-id": {message-id}}

Errors:
^^^^^^^
    :statuscode 404: `token` is invalid.
    :statuscode 202: Message stored for delivery to client at a later
                     time.
    :statuscode 200: Message delivered to node client is connected to.

Cancel Notification
~~~~~~~~~~~~~~~~~~~

Delete the message given the `message_id`.

Call:
^^^^^
.. http:delete:: /m/{message_id}

Parameters:
^^^^^^^^^^^

    None

Reply:
^^^^^^

.. code-block:: json

    {}

Errors:
^^^^^^^

    Standard error codes apply.


Update Notification
~~~~~~~~~~~~~~~~~~~

Update the message at the given `{message_id}`.


Call:
^^^^^

.. http:put:: /m/(string/message_id)

Parameters:
^^^^^^^^^^^

    This method takes the same arguments as WebPush PUT, with values
    replacing that for the provided message.

    .. note::

        In the rare condition that the client is online, and has recieved
        the message but has not acknowledged it yet; then it is possible that
        the client will not get the updated message until reconnect. This
        should be considered a rare edge-case.

Reply:
^^^^^^

.. code-block:: json

    {}

Errors:
^^^^^^^

    :statuscode 404: `message_id` is not found.
    :statuscode 200: Message has been updated.

.. _bridge_api:

Push Service Bridge HTTP Interface
==================================

Push allows for remote devices to perform some functions using an HTTP
interface. This is mostly used by devices that are bridging via an
external protocol like
`GCM <https://developers.google.com/cloud-messaging/>`__ or
`APNs <https://developer.apple.com/library/ios/documentation/NetworkingIntern\
et/Conceptual/RemoteNotificationsPG/Introduction.html#//apple_ref/doc/uid/TP4\
0008196-CH1-SW1>`__. All message bodies must be UTF-8 encoded.

Lexicon
-------

For the following call definitions:

   :{type}: The bridge type.

Allowed bridges are `gcm` (Google Cloud Messaging) and `apns` (Apple
Push Notification system)

   :{token}: The bridge specific public exchange token

Each protocol requires a unique token that addresses the remote application.
For GCM, this is the `SenderID` and is pre-negotiated outside of the push
service.

   :{instanceid}: The bridge specific private identifier token

Each protocol requires a unique token that addresses the
application on a given user's device. This is usually the product of the
application registering the {instanceid} with the native bridge protocol
agent.

   :{auth_token}: The Authorization token

Most calls to the HTTP interface require a Authorization header. The
Authorization header is a bearer token, which has been provided by the
**Registration** call and is preceded by the token type word "Bearer".

An example of the Authorization header would be:

::

    Authorization: Bearer 0123abcdef

Calls
-----

Registration
~~~~~~~~~~~~

Request a new UAID registration, Channel ID, and optionally set a bridge
type and token for this connection.

Call:
^^^^^

.. http:post:: /v1/{type}/{token}/registration

This call requires no Authorization for first time use.

Parameters:
^^^^^^^^^^^

    {"token":{instanceid}}

    .. note::

        If additional information is required for the bridge, it may be
        included in the paramters as JSON elements. Currently, no additional
        information is required.

Reply:
^^^^^^

.. code-block:: json

    `{"uaid": {UAID}, "secret": {auth_token},
    "endpoint": "https://updates-push...", "channelID": {CHID}}`

example:

.. code-block:: http

    > POST /v1/gcm/a1b2c3/registration
    >
    > {"token": "1ab2c3"}

.. code-block:: json

    < {"uaid": "abcdef012345",
    < "secret": "0123abcdef",
    < "endpoint": "https://updates-push.services.mozaws.net/push/...",
    < "channelID": "01234abcd"}

Errors:
^^^^^^^

Standard error codes apply.

Token updates
~~~~~~~~~~~~~

Update the current bridge token value

Call:
^^^^^

.. http:put:: /v1/{type}/{token}/registration/{uaid}

::

    Authorization: Bearer {auth_token}

Parameters:
^^^^^^^^^^^

    {"token": {instanceid}}

    .. note::

        If additional information is required for the bridge, it may be
        included in the paramters as JSON elements. Currently, no additional
        information is required.

Reply:
^^^^^^

.. code-block:: json

    {}

example:

.. code-block:: http

    > PUT /v1/gcm/a1b2c3/registration/abcdef012345
    > Authorization: Bearer 0123abcdef
    >
    > {"token": "5e6g7h8i"}

.. code-block:: json

    < {}

Errors:
^^^^^^^

Standard error codes apply.

Channel Subscription
~~~~~~~~~~~~~~~~~~~~

Acquire a new ChannelID for a given UAID.

Call:
^^^^^

.. http:post:: /v1/{type}/{token}/registration/{uaid}/subscription

::

    Authorization: Bearer {auth_token}

Parameters:
^^^^^^^^^^^

     {}

Reply:
^^^^^^

.. code-block:: json

    {"channelID": {CHID}, "endpoint": "https://updates-push..."}

example:

.. code-block:: http

    > POST /v1/gcm/a1b2c3/registration/abcdef012345/subscription
    > Authorization: Bearer 0123abcdef
    >
    > {}

.. code-block:: json

    < {"channelID": "43210efgh"
    < "endpoint": "https://updates-push.services.mozaws.net/push/..."}

Errors:
^^^^^^^

Standard error codes apply.

Unregister UAID (and all associated ChannelID subscriptions)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Indicate that the UAID, and by extension all associated subscriptions,
is no longer valid.

Call:
^^^^^

.. http:delete:: /v1/{type}/{token}/registration/{uaid}

::

    Authorization: Bearer {auth_token}

Parameters:
^^^^^^^^^^^

    {}

Reply:
^^^^^^

.. code-block:: json

    {}

Errors:
^^^^^^^

Standard error codes apply.

Unsubscribe Channel
~~~~~~~~~~~~~~~~~~~

Remove a given ChannelID subscription from a UAID.

Call:
^^^^^

.. http:delete:: /v1/{type}/{token}/registration/{UAID}/subscription/{CHID}

::

    Authorization: Bearer {auth_token}

Parameters:
^^^^^^^^^^^

    {}

Reply:
^^^^^^

.. code-block:: json

    {}

Errors:
^^^^^^^

Standard error codes apply.
"""
import hashlib
import json
import time
import urlparse
import uuid
import re

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
from twisted.python import log

from autopush.router.interface import RouterException
from autopush.utils import (
    generate_hash,
    validate_uaid,
    ErrorLogger
)

# Our max TTL is 60 days realistically with table rotation, so we hard-code it
MAX_TTL = 60 * 60 * 24 * 60
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


class AutoendpointHandler(ErrorLogger, cyclone.web.RequestHandler):
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
        self.request_id = str(uuid.uuid4())

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
            "request_id": self.request_id,
            "user-agent": self.request.headers.get("user-agent", ""),
            "remote-ip": self.request.headers.get("x-forwarded-for",
                                                  self.request.remote_ip),
            "authorization": self.request.headers.get("authorization", ""),
            "uaid_hash": self.uaid_hash,
            "router_key": getattr(self, "router_key", ""),
            "channel_id": getattr(self, "chid", ""),
        }

    #############################################################
    #                    Error Callbacks
    #############################################################
    def _write_response(self, status_code, errno, message=None, headers=None):
        """Writes out a full JSON error and sets the appropriate status"""
        self.set_status(status_code)
        error_data = dict(
            code=status_code,
            errno=errno,
            error=status_codes.get(status_code, "")
        )
        if message:
            error_data["message"] = message
        self.write(json.dumps(error_data))
        self.set_header("Content-Type", "application/json")
        if headers:
            for header in headers.keys():
                self.set_header(header, headers.get(header))
        self.finish()

    def _response_err(self, fail):
        """errBack for all exceptions that should be logged

        This traps all exceptions to prevent any further callbacks from
        running.

        """
        log.err(fail, **self._client_info())
        self._write_response(500, 999)

    def _overload_err(self, fail):
        """errBack for throughput provisioned exceptions"""
        fail.trap(ProvisionedThroughputExceededException)
        log.msg("Throughput Exceeded", **self._client_info())
        self._write_response(503, 201)

    def _router_response(self, response):
        for name, val in response.headers.items():
            self.set_header(name, val)
        if 200 <= response.status_code < 300:
            self.set_status(response.status_code)
            self.write(response.response_body)
            self.finish()
        else:
            return self._write_response(
                response.status_code,
                errno=response.errno or 999,
                message=response.response_body)

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
        log.msg("UAID not found in AWS.", **self._client_info())
        self._write_response(404, 103)

    def _token_err(self, fail):
        """errBack for token decryption fail"""
        fail.trap(InvalidToken, ValueError)
        log.msg("Invalid token", **self._client_info())
        self._write_response(404, 102)

    def _chid_not_found_err(self, fail):
        """errBack for unknown chid"""
        fail.trap(ItemNotFound, ValueError)
        log.msg("CHID not found in AWS.", **self._client_info())
        self._write_response(404, 106)

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
    cors_methods = "DELETE,PUT"
    cors_request_headers = ["content-encoding", "encryption",
                            "encryption-key", "content-type"]
    cors_response_headers = ["location"]

    def _token_valid(self, result, func):
        """Handles valid token processing, then dispatches to supplied
        function"""
        info = result.split(":")
        if len(info) != 3:
            raise ValueError("Wrong message token components")

        kind, uaid, chid = info
        if kind != 'm':
            raise ValueError("Wrong message token kind")
        return func(kind, uaid, chid)

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
        d.addCallback(self._token_valid, self._delete_message)
        d.addErrback(self._token_err)
        d.addErrback(self._response_err)
        return d

    def _delete_message(self, kind, uaid, chid):
        d = deferToThread(self.ap_settings.message.delete_message, uaid,
                          chid, self.version)
        d.addCallback(self._delete_completed)
        self._db_error_handling(d)
        return d

    def _delete_completed(self, response):
        self.set_status(204)
        self.finish()

    @cyclone.web.asynchronous
    def put(self, token):
        """Updates a pending message.

        If the message was already acknowledged, then this will instead create
        a new message.

        """
        self.version = token
        d = deferToThread(self.ap_settings.fernet.decrypt,
                          self.version.encode('utf8'))
        d.addCallback(self._token_valid, self._put_message)
        d.addErrback(self._token_err)
        d.addErrback(self._response_err)
        return d

    def _put_message(self, kind, uaid, chid):
        try:
            ttl = int(self.request.headers.get("ttl", "0"))
            # Cap the TTL to our MAX_TTL
            ttl = min(ttl, MAX_TTL)
        except ValueError:
            ttl = 0
        data = self.request.body
        if data and len(data) > self.ap_settings.max_data:
            log.msg("Data too large", **self._client_info())
            return self._write_response(
                413, 104, message="Data payload too large")

        headers = None
        if data:
            req_fields = ["content-encoding", "encryption"]
            if not all([x in self.request.headers for x in req_fields]):
                log.msg("Missing Crypto headers", **self._client_info())
                return self._write_response(400, 101)

            headers = dict(
                encoding=self.request.headers["content-encoding"],
                encryption=self.request.headers["encryption"],
            )
            data = urlsafe_b64encode(self.request.body)
            # AWS cannot store empty strings, so we only add the encryption-key
            # if its present to avoid empty strings.
            if "encryption-key" in self.request.headers:
                headers["encryption_key"] = \
                    self.request.headers["encryption-key"]

        d = deferToThread(self.ap_settings.message.update_message, uaid,
                          chid, self.version, ttl=ttl, data=data,
                          headers=headers)
        d.addCallback(self._put_completed, uaid, chid, data, ttl, headers)
        self._db_error_handling(d)

    def _put_completed(self, result, uaid, chid, data, ttl, headers):
        if result:
            self.set_header("TTL", str(ttl))
            self.set_status(201)
            self.write("Accepted")
            return self.finish()
        else:
            return self._write_response(404, 107, message="Message not found")


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

        try:
            self.router = self.ap_settings.routers[router_key]
        except KeyError:
            return self._write_response(400, 108,
                                        message="Invalid router type")

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
                    log.msg("Missing Crypto headers", **self._client_info())
                    return self._write_response(400, 101)

        try:
            ttl = int(self.request.headers.get("ttl", "0"))
            # Cap the TTL to our MAX_TTL
            ttl = min(ttl, MAX_TTL)
        except ValueError:
            ttl = 0
        if data and len(data) > self.ap_settings.max_data:
            return self._write_response(
                413, 104, message="Data payload too large")

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
    cors_methods = "POST,PUT,DELETE"
    _base_tags = []

    def base_tags(self):
        tags = self._base_tags
        tags.append("user-agent:%s" %
                    self.request.headers.get("user-agent"))

    def _relocate(self, router_type, router_token, uaid="", chid=""):
        relo = "%s/v1/%s/%s/register" % (self.ap_settings.endpoint_url,
                                         router_type, router_token)
        if uaid:
            relo += "/%s" % uaid
        if chid:
            relo += "/subscription/%s" % chid
        return relo

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    @cyclone.web.asynchronous
    def post(self, router_type="", router_token="", uaid="", chid=""):
        """HTTP POST

        Endpoint generation and optionally router type/data registration.

        """

        self.start_time = time.time()
        self.add_header("Content-Type", "application/json")
        params = self._load_params()
        # If the client didn't provide a CHID, make one up.
        if chid:
            params["channelID"] = chid
        if "channelID" not in params:
            params["channelID"] = uuid.uuid4().hex
        self.ap_settings.metrics.increment("updates.client.register",
                                           tags=self.base_tags())
        # If there's a UAID, ensure its valid, otherwise we ensure the hash
        # matches up
        new_uaid = False

        # normalize the path vars into parameters
        if router_type not in self.ap_settings.routers:
            log.msg("Invalid parameters", **self._client_info())
            return self._write_response(
                400, 108, message="Invalid arguments")
        router = self.ap_settings.routers[router_type]
        valid, router_token = router.check_token(router_token)
        if not valid:
            newUrl = self._relocate(router_type, router_token, uaid, chid)
            return self._write_response(
                301, 0, message=("Location: %s" % newUrl),
                headers={"Location": newUrl})

        if uaid:
            if not self._validate_auth(uaid):
                return self._write_response(
                    401, 109, message="Unauthorized")
        else:
            # No UAID supplied, make our own
            uaid = uuid.uuid4().hex
            new_uaid = True
            # Should this be different than websocket?
        self.uaid = uaid
        self.chid = params["channelID"]
        if new_uaid:
            d = Deferred()
            d.addCallback(router.register, params)
            d.addCallback(self._save_router_data, router_type)
            d.addCallback(self._create_endpoint)
            d.addCallback(self._return_endpoint, new_uaid, router)
            d.addErrback(self._router_fail_err)
            d.addErrback(self._response_err)
            d.callback(uaid)
        else:
            d = self._create_endpoint()
            d.addCallback(self._return_endpoint, new_uaid)
            d.addErrback(self._response_err)

    @cyclone.web.asynchronous
    def put(self, router_type="", router_token="", uaid="", chid=""):
        """HTTP PUT

        Update router type/data for a UAID.

        """
        self.start_time = time.time()

        if not self._validate_auth(uaid):
            return self._write_response(
                401, 109, message="Invalid Authentication")

        params = self._load_params()
        self.uaid = uaid
        router_data = params
        if router_type not in self.ap_settings.routers or not router_data:
            log.msg("Invalid parameters", **self._client_info())
            return self._write_response(
                400, 108, message="Invalid arguments")
        router = self.ap_settings.routers[router_type]
        valid, router_token = router.check_token(router_token)
        if not valid:
            newUrl = self._relocate(router_type, router_token, uaid, chid)
            return self._write_response(
                301, 0, "Location: %s" % newUrl,
                headers={"Location": newUrl})

        self.add_header("Content-Type", "application/json")
        d = Deferred()
        d.addCallback(router.register, router_data)
        d.addCallback(self._save_router_data, router_type)
        d.addCallback(self._success)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        d.callback(uaid)

    def _delete_channel(self, uaid, chid):
        message = self.ap_settings.message
        message.delete_messages_for_channel(uaid, chid)
        if not message.unregister_channel(uaid, chid):
            raise ItemNotFound("ChannelID not found")

    def _delete_uaid(self, uaid, router):
        message = self.ap_settings.message
        message.delete_user(uaid)
        if not router.drop_user(uaid):
            raise ItemNotFound("UAID not found")

    def _register_channel(self):
        self.ap_settings.message.register_channel(self.uaid, self.chid)
        endpoint = self.ap_settings.make_endpoint(self.uaid, self.chid)
        return endpoint

    @cyclone.web.asynchronous
    def delete(self, router_type="", router_token="", uaid="", chid=""):
        """HTTP DELETE

        Invalidate a UAID (and all channels associated with it).

        """
        if not self._validate_auth(uaid):
            return self._write_response(
                401, 109, message="Invalid Authentication")
        if router_type not in self.ap_settings.routers:
            log.msg("Invalid parameters", **self._client_info())
            return self._write_response(
                400, 108, message="Invalid arguments")
        router = self.ap_settings.routers[router_type]
        valid, router_token = router.check_token(router_token)
        if not valid:
            newUrl = self._relocate(router_type, router_token, uaid, chid)
            return self._write_response(
                301, 0, "Location: %s" % newUrl,
                headers={"Location": newUrl})

        if chid:
            # mark channel as dead
            self.ap_settings.metrics.increment("updates.client.unregister",
                                               tags=self.base_tags())
            d = deferToThread(self._delete_channel, uaid, chid)
            d.addCallback(self._success)
            d.addErrback(self._chid_not_found_err)
            d.addErrback(self._response_err)
            return d
        # nuke uaid
        d = deferToThread(self._delete_uaid, uaid,
                          self.ap_settings.router)
        d.addCallback(self._success)
        d.addErrback(self._uaid_not_found_err)
        d.addErrback(self._response_err)
        return d

    #############################################################
    #                    Callbacks
    #############################################################
    def _save_router_data(self, router_data, router_type):
        """Called when new data needs to be saved to a user-record"""
        user_item = dict(
            uaid=self.uaid,
            router_type=router_type,
            router_data=router_data,
            connected_at=int(time.time() * 1000),
        )
        return deferToThread(self.ap_settings.router.register_user, user_item)

    def _create_endpoint(self, result=None):
        """Called to register a new channel and create its endpoint."""
        return deferToThread(self._register_channel)

    def _return_endpoint(self, endpoint, new_uaid, router=None):
        """Called after the endpoint was made and should be returned to the
        requestor"""
        if new_uaid:
            if self.ap_settings.auth_key:
                hashed = generate_hash(self.ap_settings.auth_key[0],
                                       self.uaid)
            msg = dict(
                uaid=self.uaid,
                secret=hashed,
                channelID=self.chid,
                endpoint=endpoint,
            )
            # Apply any router specific fixes to the outbound response.
            if router is not None:
                msg = router.amend_msg(msg)
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
        """Validates the Authorization header in a request

        Validate the given request bearer token
        """

        test, _ = validate_uaid(uaid)
        if not test:
            return False
        header = self.request.headers.get("Authorization")
        if header is None:
            return False
        try:
            token_type, rtoken = re.sub(r' +', ' ',
                                        header.strip()).split(" ", 2)
        except ValueError:
            return False
        if "bearer" != token_type.lower():
            return False
        if self.ap_settings.auth_key:
            for key in self.ap_settings.auth_key:
                token = generate_hash(key, uaid)
                if rtoken == token:
                    return True
            return False
        else:
            return True

    def _load_params(self):
        """Load and parse a JSON body out of the request body, or return an
        empty dict"""
        try:
            return json.loads(self.request.body)
        except ValueError:
            return {}
