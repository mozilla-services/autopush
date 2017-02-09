import re
import time

from boto.dynamodb2.exceptions import ItemNotFound
from cryptography.fernet import InvalidToken
from jose import JOSEError
from marshmallow import (
    Schema,
    fields,
    pre_load,
    post_load,
    validates,
    validates_schema,
)
from marshmallow_polyfield import PolyField
from marshmallow.validate import OneOf
from twisted.logger import Logger  # noqa
from twisted.internet.defer import Deferred
from twisted.internet.threads import deferToThread

from autopush.crypto_key import CryptoKey
from autopush.db import dump_uaid, hasher
from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
    VapidAuthException,
)
from autopush.settings import AutopushSettings  # noqa
from autopush.utils import (
    base64url_encode,
    extract_jwt,
    ms_time,
    WebPushNotification,
    normalize_id,
)
from autopush.web.base import (
    AUTH_SCHEMES,
    threaded_validate,
    BaseWebHandler,
    PREF_SCHEME,
)

MAX_TTL = 60 * 60 * 24 * 60

# Base64 URL validation
VALID_BASE64_URL = re.compile(r'^[0-9A-Za-z\-_]+=*$')


class WebPushSubscriptionSchema(Schema):
    uaid = fields.UUID(required=True)
    chid = fields.UUID(required=True)
    public_key = fields.Raw(missing=None)

    @pre_load
    def extract_subscription(self, d):
        try:
            result = self.context["settings"].parse_endpoint(
                token=d["token"],
                version=d["api_ver"],
                ckey_header=d["ckey_header"],
                auth_header=d["auth_header"],
            )
        except (VapidAuthException):
            raise InvalidRequest("missing authorization header",
                                 status_code=401, errno=109)
        except (InvalidTokenException, InvalidToken):
            raise InvalidRequest("invalid token", status_code=404, errno=102)
        return result

    @validates_schema(skip_on_field_errors=True)
    def validate_uaid_month_and_chid(self, d):
        settings = self.context["settings"]  # type: AutopushSettings
        try:
            result = settings.router.get_uaid(d["uaid"].hex)
        except ItemNotFound:
            raise InvalidRequest("UAID not found", status_code=410, errno=103)

        if result.get("router_type") not in ["webpush", "gcm", "apns", "fcm"]:
            raise InvalidRequest("Wrong URL for user", errno=108)

        if result.get("critical_failure"):
            raise InvalidRequest("Critical Failure: %s" %
                                 result.get("critical_failure"),
                                 status_code=410,
                                 errno=105)

        if result["router_type"] == "webpush":
            self._validate_webpush(d, result)

        # Propagate the looked up user data back out
        d["user_data"] = result

    def _validate_webpush(self, d, result):
        settings = self.context["settings"]  # type: AutopushSettings
        log = self.context["log"]  # type: Logger
        channel_id = normalize_id(d["chid"])
        uaid = result["uaid"]
        if 'current_month' not in result:
            log.info(format="Dropping User", code=102,
                     uaid_hash=hasher(uaid),
                     uaid_record=dump_uaid(result))
            settings.router.drop_user(uaid)
            raise InvalidRequest("No such subscription", status_code=410,
                                 errno=106)

        month_table = result["current_month"]
        if month_table not in settings.message_tables:
            log.info(format="Dropping User", code=103,
                     uaid_hash=hasher(uaid),
                     uaid_record=dump_uaid(result))
            settings.router.drop_user(uaid)
            raise InvalidRequest("No such subscription", status_code=410,
                                 errno=106)
        exists, chans = settings.message_tables[month_table].all_channels(
            uaid=uaid)

        if (not exists or channel_id.lower() not
                in map(lambda x: normalize_id(x), chans)):
            log.info("Unknown subscription: {channel_id}",
                     channel_id=channel_id)
            raise InvalidRequest("No such subscription", status_code=410,
                                 errno=106)


class WebPushBasicHeaderSchema(Schema):
    authorization = fields.String()
    ttl = fields.Integer(required=False, missing=None)
    topic = fields.String(required=False, missing=None)
    api_ver = fields.String()

    @validates('topic')
    def validate_topic(self, value):
        if value is None:
            return True

        if len(value) > 32:
            raise InvalidRequest("Topic must be no greater than 32 "
                                 "characters", errno=113)

        if not VALID_BASE64_URL.match(value):
            raise InvalidRequest("Topic must be URL and Filename safe Base"
                                 "64 alphabet", errno=113)

    @post_load
    def cap_ttl(self, d):
        if 'ttl' in d:
            d["ttl"] = min(d["ttl"], MAX_TTL)


class WebPushCrypto01HeaderSchema(Schema):
    """Validates WebPush Message Encryption

    Uses draft-ietf-webpush-encryption-01 rules for validation.

    """
    content_encoding = fields.String(
        required=True,
        load_from="content-encoding",
        validate=OneOf(["aesgcm128"])
    )
    encryption = fields.String(required=True)
    encryption_key = fields.String(
        required=True,
        load_from="encryption-key"
    )
    crypto_key = fields.String(load_from="crypto-key")

    @validates("encryption")
    def validate_encryption(self, value):
        """Must contain a salt value"""
        salt = CryptoKey.parse_and_get_label(value, "salt")
        if not salt or not VALID_BASE64_URL.match(salt):
            raise InvalidRequest("Invalid salt value in Encryption header",
                                 status_code=400,
                                 errno=110)

    @validates("crypto_key")
    def validate_crypto_key(self, value):
        """Must not contain a dh value"""
        dh = CryptoKey.parse_and_get_label(value, "dh")
        if dh:
            raise InvalidRequest(
                "dh value in Crypto-Key header not valid for 01 or earlier "
                "webpush-encryption",
                status_code=400,
                errno=110,
            )

    @validates("encryption_key")
    def validate_encryption_key(self, value):
        """Must contain a dh value"""
        dh = CryptoKey.parse_and_get_label(value, "dh")
        if not dh or not VALID_BASE64_URL.match("dh"):
            raise InvalidRequest("Invalid dh value in Encryption-Key header",
                                 status_code=400,
                                 errno=110)


class WebPushCrypto04HeaderSchema(Schema):
    """Validates WebPush Message Encryption

    Uses draft-ietf-webpush-encryption-04 rules for validation.

    """
    content_encoding = fields.String(
        required=True,
        load_from="content-encoding",
        validate=OneOf(["aesgcm"])
    )
    encryption = fields.String(required=True)
    crypto_key = fields.String(
        required=True,
        load_from="crypto-key",
    )

    @validates("encryption")
    def validate_encryption(self, value):
        """Must contain a salt value"""
        salt = CryptoKey.parse_and_get_label(value, "salt")
        if not salt or not VALID_BASE64_URL.match(salt):
            raise InvalidRequest("Invalid salt value in Encryption header",
                                 status_code=400,
                                 errno=110)

    @validates("crypto_key")
    def validate_crypto_key(self, value):
        """Must contain a dh value"""
        dh = CryptoKey.parse_and_get_label(value, "dh")
        if not dh or not VALID_BASE64_URL.match("dh"):
            raise InvalidRequest("Invalid dh value in Encryption-Key header",
                                 status_code=400,
                                 errno=110)

    @validates_schema(pass_original=True)
    def reject_encryption_key(self, data, original_data):
        if "encryption-key" in original_data:
            raise InvalidRequest(
                "Encryption-Key header not valid for 02 or later "
                "webpush-encryption",
                status_code=400,
                errno=110,
            )


class WebPushInvalidContentEncodingSchema(Schema):
    """Returned to raise an Invalid Content-encoding error"""
    @validates_schema
    def invalid_content_encoding(self, d):
        raise InvalidRequest(
            "Unknown Content-Encoding",
            status_code=400,
            errno=110
        )


def conditional_crypto_deserialize(object_dict, parent_object_dict):
    """Return the WebPush Crypto Schema if there's a data payload"""
    if parent_object_dict.get("body"):
        encoding = object_dict.get("content-encoding")
        # Validate the crypto headers appropriately
        if encoding == "aesgcm128":
            return WebPushCrypto01HeaderSchema()
        elif encoding == "aesgcm":
            return WebPushCrypto04HeaderSchema()
        else:
            return WebPushInvalidContentEncodingSchema()
    else:
        return Schema()


class WebPushRequestSchema(Schema):
    subscription = fields.Nested(WebPushSubscriptionSchema,
                                 load_from="token_info")
    headers = fields.Nested(WebPushBasicHeaderSchema)
    crypto_headers = PolyField(
        load_from="headers",
        deserialization_schema_selector=conditional_crypto_deserialize,
    )
    body = fields.Raw()
    token_info = fields.Raw()

    @validates('body')
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
            ckey_header=d["headers"].get("crypto-key", ""),
            auth_header=d["headers"].get("authorization", ""),
        )
        return d

    def validate_auth(self, d):
        auth = d["headers"].get("authorization")
        needs_auth = d["token_info"]["api_ver"] == "v2"
        if not auth and not needs_auth:
            return

        public_key = d["subscription"].get("public_key")
        try:
            auth_type, token = auth.split(' ', 1)
        except ValueError:
            raise InvalidRequest("Invalid Authorization Header",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})

        # If its not a bearer token containing what may be JWT, stop
        if auth_type.lower() not in AUTH_SCHEMES or '.' not in token:
            if needs_auth:
                raise InvalidRequest("Missing Authorization Header",
                                     status_code=401, errno=109)
            return

        try:
            jwt = extract_jwt(token, public_key)
        except (AssertionError, ValueError, JOSEError):
            raise InvalidRequest("Invalid Authorization Header",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})
        if "exp" not in jwt:
            raise InvalidRequest("Invalid bearer token: No expiration",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})

        try:
            jwt_expires = int(jwt['exp'])
        except ValueError:
            raise InvalidRequest("Invalid bearer token: Invalid expiration",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})

        now = time.time()
        jwt_has_expired = now > jwt_expires
        if jwt_has_expired:
            raise InvalidRequest("Invalid bearer token: Auth expired",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})
        jwt_too_far_in_future = (jwt_expires - now) > (60*60*24)
        if jwt_too_far_in_future:
            raise InvalidRequest("Invalid bearer token: Auth > 24 hours in "
                                 "the future",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})
        jwt_crypto_key = base64url_encode(public_key)
        d["jwt"] = dict(jwt_crypto_key=jwt_crypto_key, jwt_data=jwt)

    @post_load
    def fixup_output(self, d):
        # Verify authorization
        # Note: This has to be done here, since schema validation takes place
        #       before nested schemas, and in this case we need all the nested
        #       schema logic to run first.
        self.validate_auth(d)

        # Merge crypto headers back in
        if d["crypto_headers"]:
            d["headers"].update(
                {k.replace("_", "-"): v for k, v in
                 d["crypto_headers"].items()}
            )

        # Base64-encode data for Web Push
        d["body"] = base64url_encode(d["body"])

        # Set the notification based on the validated request schema data
        d["notification"] = WebPushNotification.from_webpush_request_schema(
            data=d, fernet=self.context["settings"].fernet,
            legacy=self.context["settings"]._notification_legacy,
        )

        return d


class WebPushHandler(BaseWebHandler):
    cors_methods = "POST"
    cors_request_headers = ("content-encoding", "encryption",
                            "crypto-key", "ttl",
                            "encryption-key", "content-type",
                            "authorization")
    cors_response_headers = ("location", "www-authenticate")

    @threaded_validate(WebPushRequestSchema)
    def post(self, *args, **kwargs):
        # Store Vapid info if present
        jwt = self.valid_input.get("jwt")
        if jwt:
            self._client_info["jwt_crypto_key"] = jwt["jwt_crypto_key"]
            for i in jwt["jwt_data"]:
                self._client_info["jwt_" + i] = jwt["jwt_data"][i]

        user_data = self.valid_input["subscription"]["user_data"]
        router = self.ap_settings.routers[user_data["router_type"]]
        notification = self.valid_input["notification"]
        self._client_info["message_id"] = notification.message_id
        self._client_info["uaid"] = hasher(user_data.get("uaid"))
        self._client_info["channel_id"] = user_data.get("chid")
        self._client_info["router_key"] = user_data["router_type"]
        self._client_info["message_size"] = len(notification.data or "")
        self._client_info["ttl"] = notification.ttl
        self._client_info["version"] = notification.version
        self._router_time = time.time()
        d = Deferred()
        d.addCallback(router.route_notification, user_data)
        d.addCallback(self._router_completed, user_data, "")
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)

        # Call the prepared router
        d.callback(notification)

    def _router_completed(self, response, uaid_data, warning=""):
        """Called after router has completed successfully"""
        # Log the time taken for routing
        self._timings["route_time"] = time.time() - self._router_time
        # Were we told to update the router data?
        time_diff = time.time() - self._start_time
        if response.router_data is not None:
            if not response.router_data:
                # An empty router_data object indicates that the record should
                # be deleted. There is no longer valid route information for
                # this record.
                self.log.info(format="Dropping User", code=100,
                              uaid_hash=hasher(uaid_data["uaid"]),
                              uaid_record=dump_uaid(uaid_data),
                              client_info=self._client_info)
                d = deferToThread(self.ap_settings.router.drop_user,
                                  uaid_data["uaid"])
                d.addCallback(lambda x: self._router_response(response))
                return d
            # The router data needs to be updated to include any changes
            # requested by the bridge system
            uaid_data["router_data"] = response.router_data
            # set the AWS mandatory data
            uaid_data["connected_at"] = ms_time()
            d = deferToThread(self.ap_settings.router.register_user,
                              uaid_data)
            response.router_data = None
            d.addCallback(lambda x: self._router_completed(
                response,
                uaid_data,
                warning))
            return d
        else:
            # No changes are requested by the bridge system, proceed as normal
            if response.status_code == 200 or response.logged_status == 200:
                self.log.info(format="Successful delivery",
                              client_info=self._client_info)
            elif response.status_code == 202 or response.logged_status == 202:
                self.log.info(
                    format="Router miss, message stored.",
                    client_info=self._client_info)
            self.metrics.timing("updates.handled", duration=time_diff)
            response.response_body = (
                response.response_body + " " + warning).strip()
            self._router_response(response)
