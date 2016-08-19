"""Validation handler and Schemas"""
import re
import time
import urlparse
from functools import wraps

from boto.dynamodb2.exceptions import (
    ItemNotFound,
)
from cryptography.fernet import InvalidToken
from marshmallow import (
    Schema,
    fields,
    pre_load,
    post_load,
    validates,
    validates_schema,
)
from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
)
from autopush.utils import (
    base64url_encode,
    extract_jwt,
)

MAX_TTL = 60 * 60 * 24 * 60
# Older versions used "bearer", newer specification requires "webpush"
AUTH_SCHEMES = ["bearer", "webpush"]
PREF_SCHEME = "webpush"


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
        schema = self.schema()
        schema.context["settings"] = request_handler.ap_settings
        schema.context["log"] = self.log
        return schema.load(data)

    def _call_func(self, result, func, request_handler, *args, **kwargs):
        output, errors = result
        if errors:
            request_handler._write_validation_err(errors)
        else:
            request_handler.valid_input = output
            return func(request_handler, *args, **kwargs)

    def _decorator(self, func):
        @wraps(func)
        def wrapper(request_handler, *args, **kwargs):
            # Wrap the handler in @cyclone.web.synchronous
            request_handler._auto_finish = False

            d = deferToThread(self._validate_request, request_handler)
            d.addCallback(self._call_func, func, request_handler, *args,
                          **kwargs)
            d.addErrback(request_handler._overload_err)
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

        .. code-block::

            class MyHandler(cyclone.web.RequestHandler):
                @threaded_validate(MySchema())
                def post(self):
                    ...

        """
        return cls(schema)._decorator


# Alias to the validation classmethod decorator
threaded_validate = ThreadedValidate.validate


# Remove trailing padding characters from complex header items like
# Crypto-Key and Encryption
strip_padding = re.compile('=+(?=[,;]|$)')


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
            )
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
                raise InvalidRequest("Client error", errno=110)
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
        )
        return d

    def validate_auth(self, d):
        auth = d["headers"].get("authorization")
        if not auth:
            return

        public_key = d["subscription"].get("public_key")
        try:
            (auth_type, token) = auth.split(' ', 1)
        except ValueError:
            raise InvalidRequest("Invalid Authorization Header",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})

        # If its not a bearer token containing what may be JWT, stop
        if auth_type.lower() not in AUTH_SCHEMES or '.' not in token:
            return

        try:
            jwt = extract_jwt(token, public_key)
        except ValueError:
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

        # Add a message_id
        sub = d["subscription"]
        d["message_id"] = self.context["settings"].fernet.encrypt(
            ":".join(["m", sub["uaid"].hex, sub["chid"].hex]).encode('utf8')
        )

        # Strip crypto/encryption headers down
        for hdr in ["crypto-key", "encryption"]:
            if strip_padding.search(d["headers"].get(hdr, "")):
                head = d["headers"][hdr].replace('"', '')
                d["headers"][hdr] = strip_padding.sub("", head)

        # Base64-encode data for Web Push
        d["body"] = base64url_encode(d["body"])
        return d
