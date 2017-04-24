import json
import re
import uuid
from typing import (  # noqa
    Any,
    Optional,
    Set,
    Tuple
)

from attr import attrs, attrib
from boto.dynamodb2.exceptions import ItemNotFound
from cryptography.hazmat.primitives import constant_time
from marshmallow import (
    Schema,
    fields,
    pre_load,
    post_load,
    validates_schema
)
from twisted.internet import defer
from twisted.internet.defer import Deferred  # noqa
from twisted.internet.threads import deferToThread

from autopush.db import generate_last_connect, hasher
from autopush.exceptions import InvalidRequest
from autopush.types import JSONDict  # noqa
from autopush.utils import generate_hash, ms_time
from autopush.web.base import (
    threaded_validate,
    BaseWebHandler,
    PREF_SCHEME,
    AUTH_SCHEMES
)


class RegistrationSchema(Schema):
    router_type = fields.Str()
    router_token = fields.Str()
    router_data = fields.Dict()
    uaid = fields.UUID(allow_none=True)
    chid = fields.Str(allow_none=True)
    auth = fields.Str(allow_none=True)

    @pre_load
    def extract_data(self, req):
        router_data = {}
        if req['body']:
            try:
                router_data = json.loads(req['body'])
            except ValueError:
                raise InvalidRequest("Invalid Request body",
                                     status_code=401,
                                     errno=108)

        # UAID and CHID may be empty. This can trigger different behaviors
        # in the handlers, so we can't set default values here.
        uaid = req['path_kwargs'].get('uaid')
        chid = req['path_kwargs'].get('chid', router_data.get("channelID"))
        if uaid:
            try:
                uuid.UUID(uaid)
            except (ValueError, TypeError):
                raise InvalidRequest("Invalid Request UAID",
                                     status_code=401, errno=109)
        if chid:
            try:
                uuid.UUID(chid)
            except (ValueError, TypeError):
                raise InvalidRequest("Invalid Request Channel_id",
                                     status_code=410, errno=106)

        return dict(
            router_type=req['path_kwargs'].get('router_type'),
            router_token=req['path_kwargs'].get('router_token'),
            router_data=router_data,
            uaid=uaid,
            chid=chid,
            auth=req.get('headers', {}).get("Authorization"),
        )

    @validates_schema(skip_on_field_errors=True)
    def validate_data(self, data):
        settings = self.context['settings']

        if data['router_type'] not in settings.routers:
            raise InvalidRequest("Invalid router",
                                 status_code=400,
                                 errno=108)

        if data.get('uaid'):
            request_pref_header = {'www-authenticate': PREF_SCHEME}
            try:
                settings.router.get_uaid(data['uaid'].hex)
            except ItemNotFound:
                raise InvalidRequest("UAID not found",
                                     status_code=410,
                                     errno=103)
            if not data.get('auth'):
                raise InvalidRequest("Unauthorized",
                                     status_code=401,
                                     errno=109,
                                     headers=request_pref_header)
            settings = self.context['settings']
            try:
                auth_type, auth_token = re.sub(
                    r' +', ' ', data['auth'].strip()).split(" ", 2)
            except ValueError:
                raise InvalidRequest("Invalid Authentication",
                                     status_code=401,
                                     errno=109,
                                     headers=request_pref_header)
            if auth_type.lower() not in AUTH_SCHEMES:
                raise InvalidRequest("Invalid Authentication",
                                     status_code=401,
                                     errno=109,
                                     headers=request_pref_header)
            if settings.bear_hash_key:
                is_valid = False
                for key in settings.bear_hash_key:
                    test_token = generate_hash(key, data['uaid'].hex)
                    is_valid |= constant_time.bytes_eq(bytes(test_token),
                                                       bytes(auth_token))
                if not is_valid:
                    raise InvalidRequest("Invalid Authentication",
                                         status_code=401,
                                         errno=109,
                                         headers=request_pref_header)

    @post_load
    def handler_kwargs(self, data):
        # auth not used by the handler
        data.pop('auth')
        router_type = data.pop('router_type')
        data['rinfo'] = RouterInfo(
            router=self.context['settings'].routers[router_type],
            type_=router_type,
            token=data.pop('router_token'),
            data=data.pop('router_data')
        )


@attrs(slots=True)
class RouterInfo(object):
    """Bundle of Router registration information"""

    router = attrib()  # type: Any
    type_ = attrib()   # type: str
    token = attrib()   # type: str
    data = attrib()    # type: JSONDict

    def register(self, uaid, **kwargs):
        # type: (uuid.UUID, **Any) -> None
        self.router.register(
            uaid.hex, router_data=self.data, app_id=self.token, **kwargs)

    def amend_endpoint_response(self, response):
        # type: (JSONDict) -> None
        self.router.amend_endpoint_response(response, self.data)

    @property
    def app_server_key(self):
        return self.data.get('key')


class RegistrationHandler(BaseWebHandler):
    """Handle the Bridge services endpoints"""
    cors_methods = "GET,POST,PUT,DELETE"

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    @threaded_validate(RegistrationSchema)
    def post(self, rinfo, uaid=None, chid=None):
        # type: (RouterInfo, Optional[uuid.UUID], Optional[str]) -> Deferred
        """HTTP POST

        Endpoint generation and optionally router type/data registration.

        """
        self.add_header("Content-Type", "application/json")
        self.ap_settings.metrics.increment("updates.client.register",
                                           tags=self.base_tags())

        # If the client didn't provide a CHID, make one up.
        # Note, RegistrationSchema may explicitly set "chid" to None
        # THIS VALUE MUST MATCH WHAT'S SPECIFIED IN THE BRIDGE CONNECTIONS.
        # currently hex formatted.
        if not chid:
            chid = uuid.uuid4().hex
        rinfo.data["channelID"] = chid

        if not uaid:
            uaid = uuid.uuid4()
            d = defer.execute(rinfo.register, uaid, uri=self.request.uri)
            d.addCallback(
                lambda _:
                deferToThread(self._register_user_and_channel,
                              uaid, chid, rinfo)
            )
            d.addCallback(
                self._write_endpoint, uaid, chid, rinfo, new_uaid=True)
            d.addErrback(self._router_fail_err)
            d.addErrback(self._response_err)
        else:
            d = deferToThread(self._register_channel,
                              uaid, chid, rinfo.app_server_key)
            d.addCallback(self._write_endpoint, uaid, chid, rinfo)
            d.addErrback(self._response_err)
        return d

    @threaded_validate(RegistrationSchema)
    def put(self, rinfo, uaid=None, chid=None):
        # type: (RouterInfo, Optional[uuid.UUID], Optional[str]) -> Deferred
        """HTTP PUT

        Update router type/data for a UAID.

        """
        self.add_header("Content-Type", "application/json")
        d = defer.execute(rinfo.register, uaid, uri=self.request.uri)
        d.addCallback(
            lambda _: deferToThread(self._register_user, uaid, rinfo)
        )
        d.addCallback(self._success)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        return d

    @threaded_validate(RegistrationSchema)
    def get(self, uaid=None, **kwargs):
        # type: (Optional[uuid.UUID], **Any) -> Deferred
        """HTTP GET

        Return a list of known channelIDs for a given UAID

        """
        self.add_header("Content-Type", "application/json")
        d = defer.execute(self._check_uaid, uaid)
        d.addCallback(
            lambda _:
            deferToThread(self.ap_settings.message.all_channels, str(uaid))
        )
        d.addCallback(self._write_channels, uaid)
        d.addErrback(self._uaid_not_found_err)
        d.addErrback(self._response_err)
        return d

    @threaded_validate(RegistrationSchema)
    def delete(self, uaid=None, chid=None, **kwargs):
        # type: (Optional[uuid.UUID], Optional[str], **Any) -> Deferred
        """HTTP DELETE

        Delete all pending records for the given channel or UAID

        """
        if chid:
            # mark channel as dead
            self.ap_settings.metrics.increment("updates.client.unregister",
                                               tags=self.base_tags())
            d = deferToThread(self._delete_channel, uaid, chid)
            d.addCallback(self._success)
            d.addErrback(self._chid_not_found_err)
            d.addErrback(self._response_err)
            return d
        # nuke all records for the UAID
        d = deferToThread(self._delete_uaid, uaid)
        d.addCallback(self._success)
        d.addErrback(self._uaid_not_found_err)
        d.addErrback(self._response_err)
        return d

    def _uaid_not_found_err(self, fail):
        """errBack for uaid lookup not finding the user"""
        fail.trap(ItemNotFound)
        self.log.info(format="UAID not found in AWS.",
                      status_code=410, errno=103,
                      client_info=self._client_info)
        self._write_response(410, errno=103,
                             message="Endpoint has expired. "
                                     "Do not send messages to this endpoint.")

    def _chid_not_found_err(self, fail):
        """errBack for unknown chid"""
        fail.trap(ItemNotFound, ValueError)
        self.log.info(format="CHID not found in AWS.",
                      status_code=410, errno=106,
                      **self._client_info)
        self._write_response(410, 106, message="Invalid endpoint.")

    #############################################################
    #                    Callbacks
    #############################################################
    def _delete_channel(self, uaid, chid):
        if not self.ap_settings.message.unregister_channel(uaid.hex, chid):
            raise ItemNotFound("ChannelID not found")

    def _delete_uaid(self, uaid):
        self.log.info(format="Dropping User", code=101,
                      uaid_hash=hasher(uaid.hex))
        if not self.ap_settings.router.drop_user(uaid.hex):
            raise ItemNotFound("UAID not found")

    def _check_uaid(self, uaid):
        if not uaid:
            raise ItemNotFound("UAID not found")

    def _register_user_and_channel(self, uaid, chid, rinfo):
        # type: (uuid.UUID, str, RouterInfo) -> str
        """Register a new user/channel, return its endpoint"""
        self._register_user(uaid, rinfo)
        return self._register_channel(uaid, chid, rinfo.app_server_key)

    def _register_user(self, uaid, rinfo):
        # type: (uuid.UUID, RouterInfo) -> None
        """Save a new user record"""
        self.ap_settings.router.register_user(dict(
            uaid=uaid.hex,
            router_type=rinfo.type_,
            router_data=rinfo.data,
            connected_at=ms_time(),
            last_connect=generate_last_connect(),
        ))

    def _register_channel(self, uaid, chid, app_server_key):
        # type(uuid.UUID, str, str) -> str
        """Register a new channel and create/return its endpoint"""
        self.ap_settings.message.register_channel(uaid.hex, chid)
        return self.ap_settings.make_endpoint(uaid.hex, chid, app_server_key)

    def _write_endpoint(self, endpoint, uaid, chid, rinfo, new_uaid=False):
        # type: (str, uuid.UUID, str, RouterInfo, bool) -> None
        """Write the JSON response of the created endpoint"""
        response = dict(channelID=chid, endpoint=endpoint)
        if new_uaid:
            secret = None
            if self.ap_settings.bear_hash_key:
                secret = generate_hash(
                    self.ap_settings.bear_hash_key[0], uaid.hex)
            response.update(uaid=uaid.hex, secret=secret)
            # Apply any router specific fixes to the outbound response.
            rinfo.amend_endpoint_response(response)
        self.write(json.dumps(response))
        self.log.debug("Endpoint registered via HTTP",
                       client_info=self._client_info)
        self.finish()

    def _write_channels(self, channel_info, uaid):
        # type: (Tuple[bool, Set[str]], uuid.UUID) -> None
        response = dict(
            uaid=uaid.hex,
            channelIDs=[str(uuid.UUID(x)) for x in channel_info[1]]
        )
        self.write(json.dumps(response))
        self.finish()

    def _success(self, result):
        """Writes out empty 200 response"""
        self.write({})
        self.finish()

    def base_tags(self):
        tags = list(self._base_tags)
        tags.append("user_agent:%s" %
                    self.request.headers.get("user-agent"))
        tags.append("host:%s" % self.request.host)
        return tags
