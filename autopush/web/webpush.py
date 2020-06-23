import re
import time

from cryptography.fernet import InvalidToken
from cryptography.exceptions import InvalidSignature
from marshmallow import (
    Schema,
    fields,
    pre_load,
    post_load,
    validates,
    validates_schema,
)
from marshmallow_polyfield import PolyField
from marshmallow.validate import Equal
from twisted.logger import Logger  # noqa
from twisted.internet.defer import Deferred  # noqa
from twisted.internet.defer import maybeDeferred
from twisted.internet.threads import deferToThread
from typing import (  # noqa
    Any,
    Dict,
    Optional
)
from jose import JOSEError, JWTError

from autopush.crypto_key import CryptoKey
from autopush.db import DatabaseManager  # noqa
from autopush.metrics import TaggedMetrics  # noqa
from autopush.db import hasher
from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
    ItemNotFound,
    VapidAuthException,
)
from autopush.types import JSONDict  # noqa
from autopush.utils import (
    base64url_encode,
    extract_jwt,
    ms_time,
    WebPushNotification,
    normalize_id,
    parse_auth_header,
)
from autopush.web.base import (
    threaded_validate,
    BaseWebHandler,
    PREF_SCHEME,
)

MAX_TTL = 60 * 60 * 24 * 60

# Base64 URL validation
VALID_BASE64_URL = re.compile(r'^[0-9A-Za-z\-_]+=*$')

VALID_ROUTER_TYPES = ["simplepush", "webpush", "gcm", "fcm", "apns", "adm"]


class WebPushSubscriptionSchema(Schema):
    uaid = fields.UUID(required=True)
    chid = fields.UUID(required=True)
    public_key = fields.Raw(missing=None)

    @pre_load
    def extract_subscription(self, d):
        try:
            result = self.context["conf"].parse_endpoint(
                self.context["metrics"],
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
        db = self.context["db"]  # type: DatabaseManager

        try:
            result = db.router.get_uaid(d["uaid"].hex)
        except ItemNotFound:
            raise InvalidRequest("UAID not found", status_code=410, errno=103)

        # We must have a router_type to validate the user
        router_type = result.get("router_type")
        if router_type not in VALID_ROUTER_TYPES:
            self.context["log"].debug(format="Dropping User", code=102,
                                      uaid_hash=hasher(result["uaid"]),
                                      uaid_record=repr(result))
            metrics = self.context["metrics"]
            metrics.increment(
                "updates.drop_user",
                tags=metrics.make_tags(errno=102))
            self.context["db"].router.drop_user(result["uaid"])
            raise InvalidRequest("No such subscription", status_code=410,
                                 errno=106)

        if (router_type == "gcm"
            and 'senderID' not in result.get('router_data',
                                             {}).get("creds", {})):
            # Make sure we note that this record is bad.
            result['critical_failure'] = \
                result.get('critical_failure', "Missing SenderID")
            db.router.register_user(result)

        if (router_type == "fcm"
                and 'app_id' not in result.get('router_data', {})):
            # Make sure we note that this record is bad.
            result['critical_failure'] = \
                result.get('critical_failure', "Missing SenderID")
            db.router.register_user(result)

        if result.get("critical_failure"):
            raise InvalidRequest("Critical Failure: %s" %
                                 result.get("critical_failure"),
                                 status_code=410,
                                 errno=105)
        # Some stored user records are marked as "simplepush".
        # If you encounter one, may need to tweak it a bit to get it as
        # a valid WebPush record.
        if result["router_type"] == "simplepush":
            result["router_type"] = "webpush"

        if result["router_type"] == "webpush":
            self._validate_webpush(d, result)

        # Propagate the looked up user data back out
        d["user_data"] = result

    def _validate_webpush(self, d, result):
        db = self.context["db"]  # type: DatabaseManager
        log = self.context["log"]  # type: Logger
        metrics = self.context["metrics"]  # type: TaggedMetrics
        channel_id = normalize_id(d["chid"])
        uaid = result["uaid"]
        if 'current_month' not in result:
            log.debug(format="Dropping User", code=102,
                      uaid_hash=hasher(uaid),
                      uaid_record=repr(result))
            metrics.increment("updates.drop_user",
                              tags=metrics.make_tags(errno=102))
            db.router.drop_user(uaid)
            raise InvalidRequest("No such subscription", status_code=410,
                                 errno=106)

        month_table = result["current_month"]
        if month_table not in db.message_tables:
            log.debug(format="Dropping User", code=103,
                      uaid_hash=hasher(uaid),
                      uaid_record=repr(result))
            metrics.increment("updates.drop_user",
                              tags=metrics.make_tags(errno=103))
            db.router.drop_user(uaid)
            raise InvalidRequest("No such subscription", status_code=410,
                                 errno=106)
        msg = db.message_table(month_table)
        exists, chans = msg.all_channels(uaid=uaid)

        if (not exists or channel_id.lower() not
                in map(lambda x: normalize_id(x), chans)):
            log.debug("Unknown subscription: {channel_id}",
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

    @validates('ttl')
    def validate_ttl(self, value):
        if value is not None and value < 0:
            raise InvalidRequest("TTL must be greater than 0", errno=114)

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
        validate=Equal("aesgcm128")
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

    Uses draft-ietf-httpbis-encryption-encoding-04 rules for validation.

    """
    content_encoding = fields.String(
        required=True,
        load_from="content-encoding",
        validate=Equal("aesgcm")
    )
    encryption = fields.String(required=True)
    crypto_key = fields.String(
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


class WebPushCrypto06HeaderSchema(Schema):
    """Validates WebPush Message Encryption

    Uses draft-ietf-httpbis-encryption-encoding-06 rules for validation

    """

    content_encoding = fields.String(
        required=True,
        load_from="content-encoding",
        validate=Equal("aes128gcm")
    )

    encryption = fields.String(required=False)
    crypto_key = fields.String(required=False,
                               load_from="crypto-key")

    @validates("encryption")
    def validate_encryption(self, value):
        if CryptoKey.parse_and_get_label(value, "salt"):
            raise InvalidRequest("Do not include 'salt' in aes128gcm "
                                 "Encryption header",
                                 status_code=400,
                                 errno=110)

    @validates("crypto_key")
    def validate_crypto_key(self, value):
        if CryptoKey.parse_and_get_label(value, "dh"):
            raise InvalidRequest("Do not include 'dh' in aes128gcm "
                                 "Crypto-Key header",
                                 status_code=400,
                                 errno=110)


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
        elif encoding == "aes128gcm":
            return WebPushCrypto06HeaderSchema()
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
    vapid_version = fields.String(required=False, missing=None)

    @validates('body')
    def validate_data(self, value):
        max_data = self.context["conf"].max_data
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
        crypto_exceptions = [KeyError, ValueError, TypeError,
                             VapidAuthException]

        if self.context['conf'].use_cryptography:
            crypto_exceptions.append(InvalidSignature)
        else:
            crypto_exceptions.extend([JOSEError, JWTError, AssertionError])

        auth = d["headers"].get("authorization")
        needs_auth = d["token_info"]["api_ver"] == "v2"
        if not needs_auth and not auth:
            return
        try:
            vapid_auth = parse_auth_header(auth)
            token = vapid_auth['t']
            d["vapid_version"] = "draft{:0>2}".format(
                vapid_auth['version'])
            if vapid_auth['version'] == 2:
                public_key = vapid_auth['k']
            else:
                public_key = d["subscription"].get("public_key")
            jwt = extract_jwt(
                token,
                public_key,
                is_trusted=self.context['conf'].enable_tls_auth,
                use_crypto=self.context['conf'].use_cryptography
            )
            if not isinstance(jwt, Dict):
                raise InvalidRequest("Invalid Authorization Header",
                                     status_code=401, errno=109,
                                     headers={"www-authenticate": PREF_SCHEME})
        except tuple(crypto_exceptions):
            raise InvalidRequest("Invalid Authorization Header",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})
        if "exp" not in jwt:
            raise InvalidRequest("Invalid bearer token: No expiration",
                                 status_code=401, errno=109,
                                 headers={"www-authenticate": PREF_SCHEME})

        try:
            jwt_expires = int(jwt['exp'])
        except (TypeError, ValueError):
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
            data=d, fernet=self.context["conf"].fernet,
            legacy=self.context["conf"]._notification_legacy,
        )

        return d


class WebPushHandler(BaseWebHandler):
    cors_methods = "POST"
    cors_request_headers = ("content-encoding", "encryption",
                            "crypto-key", "ttl",
                            "encryption-key", "content-type",
                            "authorization")
    cors_response_headers = ("location", "www-authenticate")

    def initialize(self):
        """Must run on initialization to set ahead of validation"""
        super(WebPushHandler, self).initialize()
        self._handling_message = True

    @threaded_validate(WebPushRequestSchema)
    def post(self,
             subscription,  # type: Dict[str, Any]
             notification,  # type: WebPushNotification
             jwt=None,      # type: Optional[JSONDict]
             **kwargs       # type: Any
             ):
        # type: (...) -> Deferred
        # Store Vapid info if present
        if jwt:
            self.metrics.increment("updates.vapid.{}".format(
                kwargs.get('vapid_version'))
            )
            self._client_info["jwt_crypto_key"] = jwt["jwt_crypto_key"]
            for i in jwt["jwt_data"]:
                self._client_info["jwt_" + i] = jwt["jwt_data"][i]

        user_data = subscription["user_data"]
        encoding = ''
        if notification.data and notification.headers:
            encoding = notification.headers.get('encoding', '')
            self.metrics.increment(
                "updates.notification.encoding.{}".format(encoding)
            )
        self._client_info.update(
            message_id=notification.message_id,
            uaid_hash=hasher(user_data.get("uaid")),
            channel_id=notification.channel_id.hex,
            router_key=user_data["router_type"],
            message_size=notification.data_length,
            message_ttl=notification.ttl,
            version=notification.version,
            encoding=encoding,
        )
        router_type = user_data["router_type"]
        router = self.routers[router_type]
        self._router_time = time.time()
        d = maybeDeferred(router.route_notification, notification, user_data)
        d.addCallback(self._router_completed, user_data, "",
                      router_type=router_type,
                      vapid=jwt)
        d.addErrback(self._router_fail_err,
                     router_type=router_type,
                     vapid=jwt is not None)
        d.addErrback(self._response_err)
        return d

    def _router_completed(self, response, uaid_data, warning="",
                          router_type=None, vapid=None):
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
                self.log.debug(format="Dropping User", code=100,
                               uaid_hash=hasher(uaid_data["uaid"]),
                               uaid_record=repr(uaid_data),
                               client_info=self._client_info)
                d = deferToThread(self.db.router.drop_user, uaid_data["uaid"])
                d.addCallback(lambda x: self._router_response(response,
                                                              router_type,
                                                              vapid))
                return d
            # The router data needs to be updated to include any changes
            # requested by the bridge system
            uaid_data["router_data"] = response.router_data
            # set the AWS mandatory data
            uaid_data["connected_at"] = ms_time()
            d = deferToThread(self.db.router.register_user, uaid_data)
            response.router_data = None
            d.addCallback(lambda x: self._router_completed(
                response,
                uaid_data,
                warning,
                router_type,
                vapid))
            return d
        else:
            # No changes are requested by the bridge system, proceed as normal
            if response.status_code == 200 or response.logged_status == 200:
                self.log.debug(format="Successful delivery",
                               client_info=self._client_info)
            elif response.status_code == 202 or response.logged_status == 202:
                self.log.debug(
                    format="Router miss, message stored.",
                    client_info=self._client_info)
            self.metrics.timing("notification.request_time",
                                duration=time_diff)
            response.response_body = (
                response.response_body + " " + warning).strip()
            self._router_response(response, router_type, vapid)
