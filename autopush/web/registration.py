import re
import uuid

from marshmallow_polyfield import PolyField
from typing import (  # noqa
    Optional,
    Set,
    Tuple,
    Dict
)

import simplejson as json
from boto.dynamodb2.exceptions import ItemNotFound
from cryptography.hazmat.primitives import constant_time
from marshmallow import (
    Schema,
    fields,
    pre_load,
    post_load,
    validate,
    validates,
    validates_schema,
)
from twisted.internet.defer import Deferred  # noqa
from twisted.internet.threads import deferToThread

from autopush.db import generate_last_connect, hasher
from autopush.exceptions import InvalidRequest, RouterException
from autopush.types import JSONDict  # noqa
from autopush.utils import generate_hash, ms_time
from autopush.web.base import (
    threaded_validate,
    BaseWebHandler,
    PREF_SCHEME,
    AUTH_SCHEMES
)


class PathUUID(fields.Field):
    """A specialized UUID deserializer for when a UUID is in the path to
    throw a 404"""
    def _deserialize(self, value, attr, data):
        try:
            return uuid.UUID(value)
        except ValueError:
            raise InvalidRequest("Invalid Path", status_code=404)


#############################################################
# Payload body validation
#############################################################
class SubInfoSchema(Schema):
    """Validates key/channelID if present"""
    key = fields.Str(allow_none=True)
    channelID = fields.UUID(allow_none=True)

    @pre_load
    def load_body(self, value):
        try:
            return json.loads(value)
        except ValueError:
            raise InvalidRequest("Invalid Request body", status_code=400,
                                 errno=108)

    @post_load
    def convert_chid(self, data):
        if "channelID" in data:
            # ALWAYS RETURN CHID AS .HEX, NO DASH
            data["channelID"] = data["channelID"].hex


class TokenSchema(SubInfoSchema):
    """Filters allowed values from body data"""
    token = fields.Str(allow_none=True)


valid_token = validate.Regexp("^[^ ]{8,}$")


class GCMTokenSchema(SubInfoSchema):
    token = fields.Str(allow_none=False,
                       validate=valid_token,
                       error="Missing required token value")


class APNSTokenSchema(SubInfoSchema):
    token = fields.Str(allow_none=False,
                       validate=valid_token,
                       error="Missing required token value")
    aps = fields.Dict(allow_none=True)


#############################################################
# URI argument validation
#############################################################
class TypeAppSchema(Schema):
    """Validates that type / app_id for the URI are valid"""
    router_type = fields.Str(required=True, load_from="type")
    app_id = fields.Str(required=True)

    @validates("router_type")
    def validate_router_type(self, value):
        if value not in self.context['routers']:
            raise InvalidRequest("Invalid router",
                                 status_code=400,
                                 errno=108)


class TypeAppUaidSchema(TypeAppSchema):
    """Validates that type / app_id / uaid for the URI are valid"""
    uaid = PathUUID(required=True)

    @validates("uaid")
    def validate_uaid(self, value):
        try:
            self.context['db'].router.get_uaid(value.hex)
        except ItemNotFound:
            raise InvalidRequest("UAID not found", status_code=410, errno=103)


class TypeAppChidUaidSchema(TypeAppUaidSchema):
    """Validates that type / app_id / uaid / chid for the URI are valid"""
    chid = PathUUID(required=True)


#############################################################
# Header validation
#############################################################
class AuthorizationHeaderSchema(Schema):
    authorization = fields.Str(load_from="Authorization")


#############################################################
# Request validation mix-ins
#############################################################
class AuthorizationCheckSchema(Schema):
    headers = fields.Nested(AuthorizationHeaderSchema)

    """Schema that does the authorization check"""
    @validates_schema(skip_on_field_errors=True)
    def validate_auth(self, data):
        request_pref_header = {'www-authenticate': PREF_SCHEME}
        auth = data["headers"].get("authorization")
        if not auth:
            raise InvalidRequest("Unauthorized", status_code=401, errno=109,
                                 headers=request_pref_header)

        try:
            auth_type, auth_token = re.sub(
                r' +', ' ', auth.strip()).split(" ", 2)
        except ValueError:
            raise InvalidRequest("Invalid Authentication", status_code=401,
                                 errno=109,
                                 headers=request_pref_header)
        if auth_type.lower() not in AUTH_SCHEMES:
            raise InvalidRequest("Invalid Authentication",
                                 status_code=401,
                                 errno=109,
                                 headers=request_pref_header)

        conf = self.context['conf']
        uaid = data["path_kwargs"]["uaid"]
        if conf.bear_hash_key:
            is_valid = False
            for key in conf.bear_hash_key:
                test_token = generate_hash(key, uaid.hex)
                is_valid |= constant_time.bytes_eq(bytes(test_token),
                                                   bytes(auth_token))
            if not is_valid:
                raise InvalidRequest("Invalid Authentication",
                                     status_code=401,
                                     errno=109,
                                     headers=request_pref_header)


def conditional_token_check(object_dict, parent_dict):
    if parent_dict['path_kwargs']['type'] in ['gcm', 'fcm']:
        return GCMTokenSchema()
    if parent_dict['path_kwargs']['type'] == 'apns':
        return APNSTokenSchema()
    return TokenSchema()


class RouterDataSchema(Schema):
    router_data = PolyField(
        load_from="body",
        deserialization_schema_selector=conditional_token_check)

    @validates_schema(skip_on_field_errors=True)
    def register_router(self, data):
        router_type = data["path_kwargs"]["router_type"]
        router = self.context["routers"][router_type]
        try:
            router.register(uaid="", router_data=data["router_data"],
                            app_id=data["path_kwargs"]["app_id"])
        except RouterException as exc:
            raise InvalidRequest(exc.message, status_code=exc.status_code,
                                 errno=exc.errno, headers=exc.headers)


#############################################################
# Handler method validators
#############################################################
class NewRegistrationSchema(RouterDataSchema):
    path_kwargs = fields.Nested(TypeAppSchema)

    @post_load
    def extract_needed(self, data):
        return dict(
            router_type=data["path_kwargs"]["router_type"],
            router_data=data["router_data"]
        )


class GetUaidChannelSchema(AuthorizationCheckSchema):
    path_kwargs = fields.Nested(TypeAppUaidSchema)

    @post_load
    def extract_needed(self, data):
        return dict(
            uaid=data["path_kwargs"]["uaid"],
        )


class TokenUpdateSchema(AuthorizationCheckSchema, RouterDataSchema):
    path_kwargs = fields.Nested(TypeAppUaidSchema)

    @post_load
    def extract_needed(self, data):
        return dict(
            router_data=data["router_data"],
            router_type=data["path_kwargs"]["router_type"],
            uaid=data["path_kwargs"]["uaid"],
        )


class UnregisterUaidSchema(AuthorizationCheckSchema):
    path_kwargs = fields.Nested(TypeAppUaidSchema)

    @post_load
    def extract_needed(self, data):
        return dict(
            uaid=data["path_kwargs"]["uaid"],
        )


class NewChidSchema(AuthorizationCheckSchema):
    body = fields.Nested(SubInfoSchema)
    path_kwargs = fields.Nested(TypeAppUaidSchema)

    @post_load
    def extract_needed(self, data):
        chid = data["body"].get("channelID", uuid.uuid4().hex)
        return dict(
            uaid=data["path_kwargs"]["uaid"],
            chid=chid,
            app_server_key=data["body"].get("key"),
        )


class UnregisterChidSchema(AuthorizationCheckSchema):
    path_kwargs = fields.Nested(TypeAppChidUaidSchema)

    @post_load
    def extract_needed(self, data):
        return dict(
            uaid=data["path_kwargs"]["uaid"],
            chid=data["path_kwargs"]["chid"],
        )
#############################################################


class BaseRegistrationHandler(BaseWebHandler):
    """Common registration handler methods"""
    def base_tags(self):
        tags = list(self._base_tags)
        tags.append("user_agent:%s" %
                    self.request.headers.get("user-agent"))
        tags.append("host:%s" % self.request.host)
        return tags

    def _register_channel(self, uaid, chid, app_server_key):
        # type: (uuid.UUID, str, Optional[str]) -> str
        """Register a new channel and create/return its endpoint"""
        self.db.message.register_channel(uaid.hex, chid)
        return self.conf.make_endpoint(uaid.hex, chid, app_server_key)

    def _register_user(self, uaid, router_type, router_data):
        # type: (uuid.UUID, str, JSONDict) -> None
        """Save a new user record"""
        self.db.router.register_user(dict(
            uaid=uaid.hex,
            router_type=router_type,
            router_data=router_data,
            connected_at=ms_time(),
            last_connect=generate_last_connect(),
        ))

    def _write_endpoint(self, endpoint, uaid, chid, router_type, router_data,
                        new_uaid=False):
        # type: (str, uuid.UUID, str, str, JSONDict, bool) -> None
        """Write the JSON response of the created endpoint"""
        response = dict(channelID=chid, endpoint=endpoint)
        if new_uaid:
            secret = None
            if self.conf.bear_hash_key:
                secret = generate_hash(self.conf.bear_hash_key[0], uaid.hex)
            response.update(uaid=uaid.hex, secret=secret)
            # Apply any router specific fixes to the outbound response.
            router = self.routers[router_type]
            router.amend_endpoint_response(response, router_data)
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(response))
        self.log.info("Register",
                      client_info=self._client_info,
                      endpoint=endpoint,
                      uaid_hash=hasher(uaid.hex))
        self.finish()

    def _success(self, result):
        """Writes out empty 200 response"""
        self.set_header("Content-Type", "application/json")
        self.write("{}")
        self.finish()


class NewRegistrationHandler(BaseRegistrationHandler):
    """Handle new bridge uaid registrations"""
    cors_methods = "POST"

    @threaded_validate(NewRegistrationSchema)
    def post(self, router_type, router_data):
        # type: (str, JSONDict) -> Deferred
        """HTTP POST

        Router type/data registration.

        """
        self.metrics.increment("ua.command.register", tags=self.base_tags())

        uaid = uuid.uuid4()

        # ALWAYS RETURN CHID AS .HEX, NO DASH
        chid = router_data.get("channelID", uuid.uuid4().hex)

        d = deferToThread(self._register_user_and_channel,
                          uaid, chid, router_type, router_data)
        d.addCallback(self._write_endpoint, uaid, chid, router_type,
                      router_data, new_uaid=True)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        return d

    def _register_user_and_channel(self, uaid, chid, router_type, router_data):
        # type: (uuid.UUID, str, str, JSONDict) -> str
        """Register a new user/channel, return its endpoint"""
        self._register_user(uaid, router_type, router_data)
        return self._register_channel(uaid, chid, router_data.get("key"))


class UaidRegistrationHandler(BaseRegistrationHandler):
    """Handles UAID bridge methods"""
    cors_methods = "GET,POST,PUT,DELETE"

    @threaded_validate(GetUaidChannelSchema)
    def get(self, uaid):
        # type: (uuid.UUID) -> Deferred
        """HTTP GET

        Return a list of known channelIDs for a given UAID

        """
        d = deferToThread(self.db.message.all_channels, str(uaid))
        d.addCallback(self._write_channels, uaid)
        d.addErrback(self._uaid_not_found_err)
        d.addErrback(self._response_err)
        return d

    @threaded_validate(TokenUpdateSchema)
    def put(self, router_type, router_data, uaid):
        # type: (str, JSONDict, uuid.UUID) -> Deferred
        """HTTP PUT

        Update router type/data for a UAID.

        """
        d = deferToThread(self._register_user, uaid, router_type, router_data)
        d.addCallback(self._success)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        return d

    post = put

    @threaded_validate(UnregisterUaidSchema)
    def delete(self, uaid):
        # type: (uuid.UUID) -> Deferred
        """HTTP DELETE

        Delete all pending records for the given UAID

        """
        d = deferToThread(self._delete_uaid, uaid)
        d.addCallback(self._success)
        d.addErrback(self._uaid_not_found_err)
        d.addErrback(self._response_err)
        return d

    def _delete_uaid(self, uaid):
        self.log.debug(format="Dropping User", code=101,
                       uaid_hash=hasher(uaid.hex))
        if not self.db.router.drop_user(uaid.hex):
            raise ItemNotFound("UAID not found")

    def _uaid_not_found_err(self, fail):
        """errBack for uaid lookup not finding the user"""
        fail.trap(ItemNotFound)
        self.log.debug(format="UAID not found in AWS.",
                       status_code=410, errno=103,
                       client_info=self._client_info)
        self._write_response(410, errno=103,
                             message="Endpoint has expired. "
                                     "Do not send messages to this endpoint.")

    def _write_channels(self, channel_info, uaid):
        # type: (Tuple[bool, Set[str]], uuid.UUID) -> None
        response = dict(
            uaid=uaid.hex,
            channelIDs=[str(uuid.UUID(x)) for x in channel_info[1]]
        )
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(response))
        self.finish()


class SubRegistrationHandler(BaseRegistrationHandler):
    """Handle a new channel for a bridge user"""
    cors_methods = "POST"

    @threaded_validate(NewChidSchema)
    def post(self, uaid, chid, app_server_key=None):
        # type: (uuid.UUID, str, Optional[str]) -> Deferred
        d = deferToThread(self._register_channel, uaid, chid, app_server_key)
        d.addCallback(self._write_endpoint, uaid, chid, "", {})
        d.addErrback(self._response_err)
        return d


class ChannelRegistrationHandler(BaseRegistrationHandler):
    """Handle deleting a channel for a bridge user"""
    cors_methods = "DELETE"

    @threaded_validate(UnregisterChidSchema)
    def delete(self, uaid, chid):
        # type: (uuid.UUID, uuid.UUID) -> Deferred
        self.metrics.increment("ua.command.unregister",
                               tags=self.base_tags())
        d = deferToThread(self._delete_channel, uaid, chid)
        d.addCallback(self._success)
        d.addErrback(self._chid_not_found_err)
        d.addErrback(self._response_err)
        return d

    def _delete_channel(self, uaid, chid):
        # type: (uuid.UUID, uuid.UUID) -> None
        if not self.db.message.unregister_channel(uaid.hex, chid.hex):
            raise ItemNotFound("ChannelID not found")
        self.log.info("Unregister",
                      client_info=self._client_info,
                      channel_id=chid.hex,
                      uaid_hash=hasher(uaid.hex))

    def _chid_not_found_err(self, fail):
        """errBack for unknown chid"""
        fail.trap(ItemNotFound, ValueError)
        self.log.debug(format="CHID not found in AWS.",
                       status_code=410, errno=106,
                       **self._client_info)
        self._write_response(410, 106, message="Invalid endpoint.")
