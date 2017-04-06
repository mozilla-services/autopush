import json
import re
import uuid
from typing import (  # noqa
    Any,
    Optional,
    Set,
    Tuple
)

from boto.dynamodb2.exceptions import ItemNotFound
from cryptography.hazmat.primitives import constant_time
from marshmallow import (
    Schema,
    fields,
    pre_load,
    validates_schema
)
from twisted.internet import defer
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
    uaid = fields.UUID(allow_none=True)
    chid = fields.Str(allow_none=True)
    router_type = fields.Str()
    router_token = fields.Str()
    router_data = fields.Dict()
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
                u_uuid = uuid.UUID(uaid)
            except (ValueError, TypeError):
                raise InvalidRequest("Invalid Request UAID",
                                     status_code=401, errno=109)
            # Check if the UAID has a 'critical error' which means that it's
            # probably invalid and should be reset/re-registered
            try:
                record = self.context['settings'].router.get_uaid(u_uuid.hex)
                if record.get('critical_failure'):
                    raise InvalidRequest("Invalid Request UAID",
                                         status_code=410, errno=105)
            except ItemNotFound:
                pass

        if chid:
            try:
                uuid.UUID(chid)
            except (ValueError, TypeError):
                raise InvalidRequest("Invalid Request Channel_id",
                                     status_code=410, errno=106)

        return dict(
            uaid=uaid,
            chid=chid,
            router_type=req['path_kwargs'].get('router_type'),
            router_token=req['path_kwargs'].get('router_token'),
            router_data=router_data,
            auth=req.get('headers', {}).get("Authorization"),
        )

    @validates_schema(skip_on_field_errors=True)
    def validate_data(self, data):
        settings = self.context['settings']
        try:
            data['router'] = settings.routers[data['router_type']]
        except KeyError:
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


class RegistrationHandler(BaseWebHandler):
    """Handle the Bridge services endpoints"""
    cors_methods = "GET,POST,PUT,DELETE"

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    @threaded_validate(RegistrationSchema)
    def post(self, *args, **kwargs):
        """HTTP POST

        Endpoint generation and optionally router type/data registration.


        """
        self.add_header("Content-Type", "application/json")

        uaid = self.valid_input['uaid']
        router = self.valid_input["router"]
        router_type = self.valid_input["router_type"]
        router_token = self.valid_input.get("router_token")
        router_data = self.valid_input['router_data']

        # If the client didn't provide a CHID, make one up.
        # Note, valid_input may explicitly set "chid" to None
        # THIS VALUE MUST MATCH WHAT'S SPECIFIED IN THE BRIDGE CONNECTIONS.
        # currently hex formatted.
        chid = router_data["channelID"] = (self.valid_input["chid"] or
                                           uuid.uuid4().hex)
        self.ap_settings.metrics.increment("updates.client.register",
                                           tags=self.base_tags())

        if not uaid:
            uaid = uuid.uuid4()
            d = defer.execute(
                router.register,
                uaid.hex, router_data=router_data, app_id=router_token,
                uri=self.request.uri)
            d.addCallback(
                lambda _:
                deferToThread(self._register_user_and_channel,
                              uaid, chid, router, router_type, router_data)
            )
            d.addCallback(self._write_endpoint,
                          uaid, chid, router, router_data)
            d.addErrback(self._router_fail_err)
            d.addErrback(self._response_err)
        else:
            d = deferToThread(self._register_channel,
                              uaid, chid, router_data.get("key"))
            d.addCallback(self._write_endpoint, uaid, chid)
            d.addErrback(self._response_err)
        return d

    @threaded_validate(RegistrationSchema)
    def put(self, *args, **kwargs):
        """HTTP PUT

        Update router type/data for a UAID.

        """
        uaid = self.valid_input['uaid']
        router = self.valid_input['router']
        router_type = self.valid_input['router_type']
        router_token = self.valid_input['router_token']
        router_data = self.valid_input['router_data']
        self.add_header("Content-Type", "application/json")
        d = defer.execute(
            router.register,
            uaid.hex, router_data=router_data, app_id=router_token,
            uri=self.request.uri)
        d.addCallback(
            lambda _:
            deferToThread(self._register_user, uaid, router_data, router_type)
        )
        d.addCallback(self._success)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        return d

    def _delete_channel(self, uaid, chid):
        message = self.ap_settings.message
        if not message.unregister_channel(uaid.hex, chid):
            raise ItemNotFound("ChannelID not found")

    def _delete_uaid(self, uaid, router):
        self.log.info(format="Dropping User", code=101,
                      uaid_hash=hasher(uaid.hex))
        if not router.drop_user(uaid.hex):
            raise ItemNotFound("UAID not found")

    def _check_uaid(self, uaid):
        if not uaid:
            raise ItemNotFound("UAID not found")

    @threaded_validate(RegistrationSchema)
    def get(self, *args, **kwargs):
        """HTTP GET

        Return a list of known channelIDs for a given UAID

        """
        uaid = self.valid_input['uaid']
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
    def delete(self, *args, **kwargs):
        """HTTP DELETE

        Delete all pending records for the given channel or UAID

        """
        if self.valid_input['chid']:
            # mark channel as dead
            self.ap_settings.metrics.increment("updates.client.unregister",
                                               tags=self.base_tags())
            d = deferToThread(self._delete_channel,
                              self.valid_input['uaid'],
                              self.valid_input['chid'])
            d.addCallback(self._success)
            d.addErrback(self._chid_not_found_err)
            d.addErrback(self._response_err)
            return d
        # nuke all records for the UAID
        d = deferToThread(self._delete_uaid, self.valid_input['uaid'],
                          self.ap_settings.router)
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
    def _register_user_and_channel(self,
                                   uaid,         # type: uuid.UUID
                                   chid,         # type: str
                                   router,       # type: Any
                                   router_type,  # type: str
                                   router_data   # type: JSONDict
                                   ):
        # type: (...) -> str
        """Register a new user/channel, return its endpoint"""
        self._register_user(uaid, router_type, router_data)
        return self._register_channel(uaid, chid, router_data.get("key"))

    def _register_user(self, uaid, router_type, router_data):
        # type: (uuid.UUID, str, JSONDict) -> None
        """Save a new user record"""
        self.ap_settings.router.register_user(dict(
            uaid=uaid.hex,
            router_type=router_type,
            router_data=router_data,
            connected_at=ms_time(),
            last_connect=generate_last_connect(),
        ))

    def _register_channel(self, uaid, chid, app_server_key):
        # type(uuid.UUID, str, str) -> str
        """Register a new channel and create/return its endpoint"""
        self.ap_settings.message.register_channel(uaid.hex, chid)
        return self.ap_settings.make_endpoint(uaid.hex, chid, app_server_key)

    def _write_endpoint(self,
                        endpoint,         # type: str
                        uaid,             # type: uuid.UUID
                        chid,             # type: str
                        router=None,      # type: Optional[Any]
                        router_data=None  # type: Optional[JSONDict]
                        ):
        # type: (...) -> None
        """Write the JSON response of the created endpoint"""
        response = dict(channelID=chid, endpoint=endpoint)
        if router_data is not None:
            # a new uaid
            secret = None
            if self.ap_settings.bear_hash_key:
                secret = generate_hash(
                    self.ap_settings.bear_hash_key[0], uaid.hex)
            response.update(uaid=uaid.hex, secret=secret)
            # Apply any router specific fixes to the outbound response.
            router.amend_endpoint_response(response, router_data)
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
