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

For a discussion on how to use the endpoints listed here, please refer
to :ref:`http`.

"""
import json
import time
import urlparse
import uuid
import re

import cyclone.web
from attr import attrs, attrib
from boto.dynamodb2.exceptions import (
    ItemNotFound,
    ProvisionedThroughputExceededException,
)
from boto.exception import BotoServerError
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import constant_time
from jose import JOSEError
from twisted.internet.defer import Deferred
from twisted.internet.threads import deferToThread

from autopush.base import BaseHandler
from autopush.db import (
    dump_uaid,
    generate_last_connect,
    hasher,
    normalize_id,
)
from autopush.exceptions import InvalidTokenException, VapidAuthException
from autopush.router.interface import RouterException
from autopush.utils import (
    generate_hash,
    validate_uaid,
    extract_jwt,
    base64url_encode,
    WebPushNotification,
)
from autopush.web.base import DEFAULT_ERR_URL
from autopush.websocket import ms_time


# Our max TTL is 60 days realistically with table rotation, so we hard-code it
MAX_TTL = 60 * 60 * 24 * 60
VALID_BASE64_URL = re.compile(r'^[0-9A-Za-z\-_]+=*$')
VALID_TTL = re.compile(r'^\d+$')
AUTH_SCHEMES = ["bearer", "webpush"]
PREF_SCHEME = "webpush"

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


@attrs
class Notification(object):
    """Parsed notification from the request"""
    version = attrib()
    data = attrib()
    channel_id = attrib()


def parse_request_params(request):
    """Parse request params from either the body or query as needed and
    return them

    :returns: Tuple of (version, data).

    """
    # If there's a request body, parse it out
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


class AutoendpointHandler(BaseHandler):
    """Common overrides for Autoendpoint handlers"""
    cors_methods = ""
    cors_request_headers = ()
    cors_response_headers = ()

    #############################################################
    #                    Cyclone API Methods
    #############################################################
    def initialize(self, ap_settings):
        """Setup basic aliases and attributes"""
        super(AutoendpointHandler, self).initialize(ap_settings)
        self.uaid_hash = self._uaid = self._chid = ""
        self.metrics = ap_settings.metrics

    def prepare(self):
        """Common request preparation"""
        if self.ap_settings.enable_tls_auth:
            self.authenticate_peer_cert()
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
                        reason=None, url=None):
        """Writes out a full JSON error and sets the appropriate status"""
        self.set_status(status_code, reason)
        error_data = dict(
            code=status_code,
            errno=errno,
            error=status_codes.get(status_code, reason or ""),
        )
        if message:
            error_data["message"] = message
        if status_code > 299 and url is None:
            error_data["more_info"] = DEFAULT_ERR_URL
        self.write(json.dumps(error_data))
        self.set_header("Content-Type", "application/json")
        if headers:
            for header in headers.keys():
                self.set_header(header, headers.get(header))
        self.finish()

    def _write_unauthorized_response(self, message="Invalid authentication",
                                     **kwargs):
        headers = {"www-authenticate": PREF_SCHEME}
        self._write_response(401, errno=109, message=message, headers=headers,
                             **kwargs)

    def _response_err(self, fail):
        """errBack for all exceptions that should be logged

        This traps all exceptions to prevent any further callbacks from
        running.

        """
        fmt = fail.value.message or 'Exception'
        self.log.failure(format=fmt, failure=fail,
                         status_code=500, errno=999, **self._client_info)
        self._write_response(500, errno=999,
                             message="Unexpected server error occurred")

    def _overload_err(self, fail):
        """errBack for throughput provisioned exceptions"""
        fail.trap(ProvisionedThroughputExceededException)
        self.log.info(format="Throughput Exceeded", status_code=503,
                      errno=201, client_info=self._client_info)
        self._write_response(503, errno=201,
                             message="Please slow message send rate")

    def _jws_err(self, fail):
        """errBack for JWS/JWT exceptions"""
        fail.trap(JOSEError)
        self.log.info(format="Authorization Failure",
                      status_code=401, errno=109,
                      client_info=self._client_info)
        self._write_response(401, errno=109,
                             message="Invalid Authorization")

    def _boto_err(self, fail):
        """errBack for random boto exceptions"""
        fail.trap(BotoServerError)
        self.log.info(format="BOTO Error: %s" % str(fail.value),
                      status_code=503, errno=202,
                      client_info=self._client_info)
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
        if isinstance(exc, RouterException):
            if exc.log_exception or exc.status_code >= 500:
                fmt = fail.value.message or 'Exception'
                self.log.failure(format=fmt,  # pragma nocover
                                 failure=fail, status_code=exc.status_code,
                                 errno=exc.errno or "",
                                 client_info=self._client_info)
            if 200 <= exc.status_code < 300:
                self.log.info(format="Success", status_code=exc.status_code,
                              logged_status=exc.logged_status or "",
                              client_info=self._client_info)
            elif 400 <= exc.status_code < 500:
                self.log.info(format="Client error",
                              status_code=exc.status_code,
                              logged_status=exc.logged_status or "",
                              errno=exc.errno or "",
                              client_info=self._client_info)
            self._router_response(exc)

    def _uaid_not_found_err(self, fail):
        """errBack for uaid lookup not finding the user"""
        fail.trap(ItemNotFound)
        self.log.info(format="UAID not found in AWS.",
                      status_code=410, errno=103,
                      client_info=self._client_info)
        self._write_response(410, errno=103,
                             message="Endpoint has expired. "
                                     "Do not send messages to this endpoint.")

    def _token_err(self, fail):
        """errBack for token decryption fail"""
        fail.trap(InvalidToken, InvalidTokenException)
        self.log.info(format="Invalid token",
                      status_code=400, errno=102,
                      client_info=self._client_info)
        self._write_response(400, 102,
                             message="Invalid endpoint.")

    def _auth_err(self, fail):
        """errBack for invalid auth token"""
        fail.trap(VapidAuthException, ValueError)
        self.log.info(format="Invalid Auth token",
                      status_code=401,
                      errno=109,
                      client_info=self._client_info)
        self._write_unauthorized_response(
            message=fail.value.message,
            url="https://datatracker.ietf.org/doc/"
                "draft-thomson-webpush-vapid/")

    def _chid_not_found_err(self, fail):
        """errBack for unknown chid"""
        fail.trap(ItemNotFound, ValueError)
        self.log.info(format="CHID not found in AWS.",
                      status_code=410, errno=106,
                      **self._client_info)
        self._write_response(410, 106, message="Invalid endpoint.")

    #############################################################
    #                    Utility Methods
    #############################################################
    def _db_error_handling(self, d):
        """Tack on the common error handling for a dynamodb request and
        uncaught exceptions"""
        d.addErrback(self._overload_err)
        d.addErrback(self._boto_err)
        d.addErrback(self._response_err)
        return d

    def _store_auth(self, jwt, crypto_key, token, result):
        if jwt.get('exp', 0) < time.time():
            raise VapidAuthException("Invalid bearer token: Auth expired")
        self._client_info["jwt_crypto_key"] = crypto_key
        for i in jwt:
            self._client_info["jwt_" + i] = jwt[i]
        return result

    def _invalid_auth(self, fail):
        if isinstance(fail.value, (JOSEError, VapidAuthException)):
            raise fail.value
        message = fail.value.message or repr(fail.value)
        if isinstance(fail.value,
                      (AssertionError, ValueError,
                       InvalidTokenException)):
            message = "A decryption error occurred"
        self.log.debug(format="Invalid bearer token: " + repr(message),
                       **self._client_info)
        raise VapidAuthException("Invalid bearer token: " + repr(message))

    def _process_auth(self, result, require_auth=False):
        """Process the optional VAPID auth token.

        VAPID requires two headers to be present;
        `Authorization: WebPush ...` and `Crypto-Key: p256ecdsa=..`.
        The problem is that VAPID is optional and Crypto-Key can carry
        content for other functions.

        """
        authorization = self.request.headers.get('authorization')
        # No auth present, so it's not a VAPID call.
        if not authorization and not require_auth:
            return result

        public_key = result.get("public_key")
        try:
            auth_type, token = authorization.split(' ', 1)
        except ValueError:
            raise VapidAuthException("Invalid Authorization header")
        # if it's a bearer token containing what may be a JWT
        if auth_type.lower() in AUTH_SCHEMES and '.' in token:
            d = deferToThread(extract_jwt, token, public_key)
            d.addCallback(self._store_auth, public_key, token, result)
            d.addErrback(self._invalid_auth)
            # error handlers already in place from calling function .put()
            return d
        # otherwise, it's not, so ignore the VAPID data if we're supposed to
        if require_auth:
            raise VapidAuthException("Invalid Authorization header",
                                     status_codes)
        return result


class MessageHandler(AutoendpointHandler):
    cors_methods = "DELETE"
    cors_response_headers = ("location",)

    @cyclone.web.asynchronous
    def delete(self, token):
        """Drops a pending message.

        The message will only be removed from DynamoDB. Messages that were
        successfully routed to a client as direct updates, but not delivered
        yet, will not be dropped.

        """
        message_id = token.encode('utf8')
        self.version = self._client_info['version'] = message_id
        d = deferToThread(self._delete_message, message_id)
        d.addCallback(self._delete_completed)
        d.addErrback(self._token_err)
        self._db_error_handling(d)
        d.addErrback(self._response_err)
        return d

    def _delete_message(self, message_id):
        notif = WebPushNotification.from_message_id(
            message_id,
            fernet=self.ap_settings.fernet,
        )
        return self.ap_settings.message.delete_message(notif)

    def _delete_completed(self, response):
        self.log.info(format="Message Deleted", status_code=204,
                      **self._client_info)
        self.set_status(204)
        self.finish()


class EndpointHandler(AutoendpointHandler):
    cors_methods = "POST,PUT"
    cors_request_headers = ("content-encoding", "encryption",
                            "crypto-key", "ttl",
                            "encryption-key", "content-type",
                            "authorization")
    cors_response_headers = ("location", "www-authenticate")

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    @cyclone.web.asynchronous
    def put(self, api_ver="v0", token=None):
        """HTTP PUT Handler

        Primary entry-point to handling a notification for a push client.

        """
        api_ver = api_ver or "v0"
        self.start_time = time.time()
        crypto_key_header = self.request.headers.get('crypto-key')
        auth_header = self.request.headers.get('authorization')
        content_encoding = self.request.headers.get('content-encoding', "")
        if content_encoding.lower() == 'aesgcm128' and crypto_key_header:
            self.log.debug(
                format="Invalid crypto state; aesgcm128 + Crypto-Key",
                status_code=400, errno=110, **self._client_info)
            wpe_url = ("https://developers.google.com/web/updates/2016/03/"
                       "web-push-encryption")
            self._write_response(
                400,
                errno=110,
                message="You're using outdated encryption; "
                "Please update to the format described in " + wpe_url)
            return

        d = deferToThread(self.ap_settings.parse_endpoint,
                          token=token,
                          version=api_ver,
                          ckey_header=crypto_key_header,
                          auth_header=auth_header)
        d.addCallback(self._process_auth, require_auth=(api_ver == "v2"))
        d.addCallback(self._token_valid)
        d.addErrback(self._jws_err)
        d.addErrback(self._auth_err)
        d.addErrback(self._token_err)
        d.addErrback(self._response_err)
    post = put

    #############################################################
    #                    Callbacks
    #############################################################
    def _token_valid(self, result):
        """Called after the token is decrypted successfully"""
        self.uaid = result.get("uaid")
        self.chid = result.get("chid")
        d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
        d.addCallback(self._uaid_lookup_results)
        d.addErrback(self._uaid_not_found_err)
        self._db_error_handling(d)

    def _uaid_lookup_results(self, uaid_data):
        """Process the result of the AWS UAID lookup"""
        # Save the whole record
        router_key = self.router_key = uaid_data.get("router_type",
                                                     "simplepush")
        self._client_info["router_key"] = router_key

        try:
            self.router = self.ap_settings.routers[router_key]
        except KeyError:
            self.log.debug(
                format="Invalid router requested", status_code=400,
                errno=108, client_info=self._client_info)
            self._write_response(400, 108, message="Invalid router")
            return

        # Only simplepush uses version/data out of body/query, GCM/APNS will
        # use data out of the request body 'WebPush' style.
        use_simplepush = router_key == "simplepush"
        topic = self.request.headers.get("topic")
        if use_simplepush:
            self.version, data = parse_request_params(self.request)
            self._client_info['message_id'] = self.version
        else:
            data = self.request.body
            # We need crypto headers for messages with payloads.
            req_fields = ["content-encoding", "encryption"]
            if data and not all([x in self.request.headers
                                 for x in req_fields]):
                self.log.debug(format="Client error", status_code=400,
                               errno=101, client_info=self._client_info)
                self._write_response(
                    400, errno=101, message="Missing necessary crypto keys.")
                return
            if ("encryption-key" in self.request.headers and
                    "crypto-key" in self.request.headers):
                self.log.debug(format="Client error", status_code=400,
                               errno=110, client_info=self._client_info)
                self._write_response(
                    400, 110, message="Invalid crypto headers")
                return
            self._client_info["message_size"] = len(data) if data else 0
            if ("crypto-key" in self.request.headers and
                    "dh=" not in self.request.headers['crypto-key']):
                self._write_response(
                    401, 110, message="Crypto-Key header missing public-key "
                    "'dh' value")
                return
            if ("encryption" in self.request.headers and
                    "salt=" not in self.request.headers['encryption']):
                self._write_response(
                    401, 110, message="Encryption header missing 'salt' value")
                return

            if topic:
                if len(topic) > 32:
                    self._write_response(
                        400, 113, message="Topic must be no greater than 32 "
                        "characters"
                    )
                    return

                if not VALID_BASE64_URL.match(topic):
                    self._write_response(
                        400, 113, message="Topic must be URL and Filename "
                        "safe Base64 alphabet"
                    )
                    return

        if VALID_TTL.match(self.request.headers.get("ttl", "0")):
            ttl = int(self.request.headers.get("ttl", "0"))
            # Cap the TTL to our MAX_TTL
            ttl = min(ttl, MAX_TTL)
        else:
            self.log.debug(format="Client error", status_code=400,
                           errno=112, client_info=self._client_info)
            self._write_response(400, 112, message="Invalid TTL header")
            return

        if data and len(data) > self.ap_settings.max_data:
            self.log.debug(format="Client error", status_code=400, errno=104,
                           client_info=self._client_info)
            self._write_response(413, 104, message="Data payload too large")
            return

        if use_simplepush:
            notification = Notification(version=self.version, data=data,
                                        channel_id=self.chid)
            self._route_notification(False, uaid_data, notification)
            return

        # Web Push and bridged messages are encrypted binary blobs. We store
        # and deliver these messages as Base64-encoded strings.
        data = base64url_encode(self.request.body)

        notification = WebPushNotification(uaid=uuid.UUID(self.uaid),
                                           channel_id=uuid.UUID(self.chid),
                                           data=data,
                                           headers=self.request.headers,
                                           ttl=ttl, topic=topic)
        if notification.data:
            notification.cleanup_headers()
        else:
            notification.headers = None

        # Generate a message ID, then route the notification.
        d = deferToThread(notification.generate_message_id,
                          self.ap_settings.fernet)
        d.addCallback(self._route_notification, uaid_data, notification)
        return d

    def _route_notification(self, webpush_message_id, uaid_data, notification):
        if webpush_message_id:
            self.version = self._client_info['message_id'] = webpush_message_id
        else:
            self.version = self._client_info['message_id'] = \
                notification.version
        d = Deferred()
        d.addCallback(self.router.route_notification, uaid_data)
        d.addCallback(self._router_completed, uaid_data)
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
                # An empty router_data object indicates that the record should
                # be deleted. There is no longer valid route information for
                # this record.
                self.log.info(format="Dropping User", code=100,
                              uaid_hash=hasher(self.uaid),
                              uaid_record=dump_uaid(uaid_data))
                d = deferToThread(self.ap_settings.router.drop_user,
                                  self.uaid)
                d.addCallback(lambda x: self._router_response(response))
                return d
            # The router data needs to be updated to include any changes
            # requested by the bridge system.
            uaid_data["router_data"] = response.router_data
            # set the AWS mandatory data.
            uaid_data["connected_at"] = ms_time()
            uaid_data["router_type"] = uaid_data.get("router_type",
                                                     self.router_key)
            d = deferToThread(self.ap_settings.router.register_user,
                              uaid_data)
            response.router_data = None
            d.addCallback(lambda x: self._router_completed(response,
                                                           uaid_data))
            return d
        else:
            # No changes are requested by the bridge system, proceed as normal
            if response.status_code == 200 or response.logged_status == 200:
                self.log.info(format="Successful delivery",
                              client_info=self._client_info)
            elif response.status_code == 202 or response.logged_status == 202:
                self.log.info(format="Router miss, message stored.",
                              client_info=self._client_info)
            time_diff = time.time() - self.start_time
            self.metrics.timing("updates.handled", duration=time_diff)
            response.response_body = (response.response_body).strip()
            self._router_response(response)


class RegistrationHandler(AutoendpointHandler):
    cors_methods = "POST,PUT,DELETE"
    _base_tags = ()

    def base_tags(self):
        tags = list(self._base_tags)
        tags.append("user_agent:%s" %
                    self.request.headers.get("user-agent"))
        tags.append("host:%s" % self.request.host)
        return tags

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
            self.log.debug(format="Invalid router requested",
                           status_code=400, errno=108,
                           client_info=self._client_info)
            self._write_response(400, 108, message="Invalid router")
            return
        router = self.ap_settings.routers[router_type]

        if uaid:
            if not self._validate_auth(uaid):
                self._write_unauthorized_response(message="Unauthorized")
                return
        else:
            # No UAID supplied, make our own
            uaid = uuid.uuid4().hex
            new_uaid = True
            # Should this be different than websocket?
        self.uaid = uaid
        self.chid = params["channelID"]
        self.app_server_key = params.get("key")
        if new_uaid:
            d = Deferred()
            d.addCallback(router.register, router_data=params,
                          app_id=router_token, uri=self.request.uri)
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
            self._write_unauthorized_response(message="Invalid Authentication")
            return

        params = self._load_params()
        self.uaid = uaid
        router_data = params
        if router_type not in self.ap_settings.routers or not router_data:
            self.log.debug(format="Invalid router requested", status_code=400,
                           errno=108, client_info=self._client_info)
            self._write_response(400, 108, message="Invalid router")
            return
        router = self.ap_settings.routers[router_type]

        self.add_header("Content-Type", "application/json")
        d = Deferred()
        d.addCallback(router.register, router_data=router_data,
                      app_id=router_token, uri=self.request.uri)
        d.addCallback(self._save_router_data, router_type)
        d.addCallback(self._success)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        d.callback(uaid)

    def _delete_channel(self, uaid, chid):
        message = self.ap_settings.message
        if not message.unregister_channel(uaid, chid):
            raise ItemNotFound("ChannelID not found")

    def _delete_uaid(self, uaid, router):
        self.log.info(format="Dropping User", code=101,
                      uaid_hash=hasher(uaid))
        if not router.drop_user(uaid):
            raise ItemNotFound("UAID not found")

    def _register_channel(self, router_data=None):
        self.ap_settings.message.register_channel(self.uaid, self.chid)
        endpoint = self.ap_settings.make_endpoint(self.uaid, self.chid,
                                                  self.app_server_key)
        return endpoint, router_data

    @cyclone.web.asynchronous
    def delete(self, router_type="", router_token="", uaid="", chid=""):
        """HTTP DELETE

        Invalidate a UAID (and all channels associated with it).

        """
        if not self._validate_auth(uaid):
            self._write_unauthorized_response(message="Invalid Authentication")
            return
        if router_type not in self.ap_settings.routers:
            self.log.debug(format="Invalid router requested",
                           status_code=400, errno=108,
                           client_info=self._client_info)
            self._write_response(400, 108, message="Invalid router")
            return

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
            connected_at=ms_time(),
            last_connect=generate_last_connect(),
        )
        return deferToThread(self.ap_settings.router.register_user, user_item)

    def _create_endpoint(self, result=None):
        """Called to register a new channel and create its endpoint."""
        router_data = None
        try:
            router_data = result[2]
        except (IndexError, TypeError):
            pass
        return deferToThread(self._register_channel, router_data)

    def _return_endpoint(self, endpoint_data, new_uaid, router=None):
        """Called after the endpoint was made and should be returned to the
        requestor"""
        hashed = None
        if new_uaid:
            if self.ap_settings.bear_hash_key:
                hashed = generate_hash(self.ap_settings.bear_hash_key[0],
                                       self.uaid)
            msg = dict(
                uaid=self.uaid,
                secret=hashed,
                channelID=self.chid,
                endpoint=endpoint_data[0],
            )
            # Apply any router specific fixes to the outbound response.
            if router is not None:
                msg = router.amend_msg(msg,
                                       endpoint_data[1].get('router_data'))
        else:
            msg = dict(channelID=self.chid, endpoint=endpoint_data[0])
        self.write(json.dumps(msg))
        self.log.debug(format="Endpoint registered via HTTP",
                       client_info=self._client_info)
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
        if token_type.lower() not in AUTH_SCHEMES:
            return False
        if self.ap_settings.bear_hash_key:
            is_valid = False
            for key in self.ap_settings.bear_hash_key:
                token = generate_hash(key, uaid)
                is_valid |= constant_time.bytes_eq(rtoken, token)
            return is_valid
        else:
            return True

    def _load_params(self):
        """Load and parse a JSON body out of the request body, or return an
        empty dict"""
        try:
            return json.loads(self.request.body)
        except ValueError:
            return {}
