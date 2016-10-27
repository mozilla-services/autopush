"""Validation handler and Schemas"""
import re
import time
import urlparse

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

from autopush.web.base import AUTH_SCHEMES, PREF_SCHEME
from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
    VapidAuthException,
)
from autopush.utils import (
    base64url_encode,
    extract_jwt,
    WebPushNotification
)

MAX_TTL = 60 * 60 * 24 * 60

# Base64 URL validation
VALID_BASE64_URL = re.compile(r'^[0-9A-Za-z\-_]+=*$')


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
    def validate_uaid(self, d):
        try:
            result = self.context["settings"].router.get_uaid(d["uaid"].hex)
        except ItemNotFound:
            raise InvalidRequest("UAID not found", status_code=410, errno=103)

        if result.get("router_type") not in ["webpush", "gcm", "apns", "fcm"]:
            raise InvalidRequest("Wrong URL for user", errno=108)

        if result.get("critical_failure"):
            raise InvalidRequest("Critical Failure: %s" %
                                 result.get("critical_failure"),
                                 status_code=410,
                                 errno=105)

        # Propagate the looked up user data back out
        d["user_data"] = result


class WebPushHeaderSchema(Schema):
    authorization = fields.String()
    crypto_key = fields.String(load_from="crypto-key")
    content_encoding = fields.String(load_from="content-encoding")
    encryption = fields.String()
    encryption_key = fields.String(load_from="encryption-key")
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

    @validates_schema
    def validate_cypto_headers(self, d):
        # Not allowed to use aesgcm128 + a crypto_key
        if (d.get("content_encoding", "").lower() == "aesgcm128" and
                d.get("crypto_key")):
            wpe_url = ("https://developers.google.com/web/updates/2016/03/"
                       "web-push-encryption")
            raise InvalidRequest(
                message="You're using outdated encryption; "
                "Please update to the format described in " + wpe_url,
                errno=110,
            )

        # These both can't be present
        if "encryption_key" in d and "crypto_key" in d:
            raise InvalidRequest("Invalid crypto headers", errno=110)

        # Cap TTL
        if 'ttl' in d:
            d["ttl"] = min(d["ttl"], MAX_TTL)

    @post_load
    def fixup_headers(self, d):
        return {k.replace("_", "-"): v for k, v in d.items()}


class WebPushRequestSchema(Schema):
    subscription = fields.Nested(WebPushSubscriptionSchema,
                                 load_from="token_info")
    headers = fields.Nested(WebPushHeaderSchema)
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

    @validates_schema(skip_on_field_errors=True)
    def ensure_encoding_with_data(self, d):
        # This runs before nested schemas, so we use the - separated
        # field name
        req_fields = ["content-encoding", "encryption"]
        if d.get("body"):
            if not all([x in d["headers"] for x in req_fields]):
                raise InvalidRequest("Client error", status_code=400,
                                     errno=110)
            if (d["headers"].get("crypto-key") and
                    "dh=" not in d["headers"]["crypto-key"]):
                    raise InvalidRequest(
                        "Crypto-Key header missing public-key 'dh' value",
                        status_code=401,
                        errno=110)
            if (d["headers"].get("encryption") and
                    "salt=" not in d["headers"]["encryption"]):
                    raise InvalidRequest(
                        "Encryption header missing 'salt' value",
                        status_code=401,
                        errno=110)

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
        except (ValueError, JOSEError):
            raise InvalidRequest("Invalid Authorization Header",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})
        if jwt.get('exp', 0) < time.time():
            raise InvalidRequest("Invalid bearer token: Auth expired",
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

        # Base64-encode data for Web Push
        d["body"] = base64url_encode(d["body"])

        # Set the notification based on the validated request schema data
        d["notification"] = WebPushNotification.from_webpush_request_schema(
            data=d, fernet=self.context["settings"].fernet,
            legacy=self.context["settings"]._notification_legacy,
        )
        return d
