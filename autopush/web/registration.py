import json
import re
import time
import uuid

from boto.dynamodb2.exceptions import ItemNotFound
from cryptography.hazmat.primitives import constant_time
from marshmallow import (
    Schema,
    fields,
    pre_load,
    validates_schema
)
from twisted.internet.defer import Deferred
from twisted.internet.threads import deferToThread

from autopush.db import generate_last_connect, hasher
from autopush.exceptions import InvalidRequest
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
    body = fields.Dict(allow_none=True)
    router_type = fields.Str()
    router_token = fields.Str()
    params = fields.Dict()
    auth = fields.Str(allow_none=True)
    vapid_info = fields.Dict(allow_none=True)

    @pre_load
    def extract_data(self, req):
        params = {}
        if req['body']:
            try:
                params = json.loads(req['body'])
            except ValueError:
                raise InvalidRequest("Invalid Request body",
                                     status_code=401,
                                     errno=108)
        # UAID and CHID may be empty. This can trigger different behaviors
        # in the handlers, so we can't set default values here.
        uaid = req['path_kwargs'].get('uaid')
        chid = req['path_kwargs'].get('chid', params.get("channelID"))
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
            auth=req.get('headers', {}).get("Authorization"),
            params=params,
            router_type=req['path_kwargs'].get('router_type'),
            router_token=req['path_kwargs'].get('router_token'),
            uaid=uaid,
            chid=chid,
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
    cors_methods = "POST,PUT,DELETE"

    #############################################################
    #                    Cyclone HTTP Methods
    #############################################################
    @threaded_validate(RegistrationSchema)
    def post(self, *args, **kwargs):
        """HTTP POST

        Endpoint generation and optionally router type/data registration.


        """
        self.start_time = time.time()
        self.add_header("Content-Type", "application/json")
        params = self.valid_input['params']
        # If the client didn't provide a CHID, make one up.
        # Note, valid_input may explicitly set "chid" to None
        # THIS VALUE MUST MATCH WHAT'S SPECIFIED IN THE BRIDGE CONNECTIONS.
        # currently hex formatted.
        self.chid = params["channelID"] = (self.valid_input["chid"] or
                                           uuid.uuid4().hex)
        self.ap_settings.metrics.increment("updates.client.register",
                                           tags=self.base_tags())
        # If there's a UAID, ensure its valid, otherwise we ensure the hash
        # matches up
        new_uaid = False

        # normalize the path vars into parameters
        router = self.ap_settings.routers[self.valid_input['router_type']]

        if not self.valid_input['uaid']:
            self.valid_input['uaid'] = uuid.uuid4()
            new_uaid = True
        self.uaid = self.valid_input['uaid']
        self.app_server_key = params.get("key")
        if new_uaid:
            d = Deferred()
            d.addCallback(router.register, router_data=params,
                          app_id=self.valid_input.get("router_token"),
                          uri=self.request.uri)
            d.addCallback(self._save_router_data,
                          self.valid_input["router_type"])
            d.addCallback(self._create_endpoint)
            d.addCallback(self._return_endpoint, new_uaid, router)
            d.addErrback(self._router_fail_err)
            d.addErrback(self._response_err)
            d.callback(self.valid_input['uaid'].hex)
        else:
            d = self._create_endpoint()
            d.addCallback(self._return_endpoint, new_uaid)
            d.addErrback(self._response_err)

    @threaded_validate(RegistrationSchema)
    def put(self, *args, **kwargs):
        """HTTP PUT

        Update router type/data for a UAID.

        """
        self.start_time = time.time()

        self.uaid = self.valid_input['uaid']
        router = self.valid_input['router']
        self.add_header("Content-Type", "application/json")
        d = Deferred()
        d.addCallback(router.register, router_data=self.valid_input['params'],
                      app_id=self.valid_input['router_token'],
                      uri=self.request.uri)
        d.addCallback(self._save_router_data, self.valid_input['router_type'])
        d.addCallback(self._success)
        d.addErrback(self._router_fail_err)
        d.addErrback(self._response_err)
        d.callback(self.valid_input['uaid'].hex)

    def _delete_channel(self, uaid, chid):
        message = self.ap_settings.message
        if not message.unregister_channel(uaid.hex, chid):
            raise ItemNotFound("ChannelID not found")

    def _delete_uaid(self, uaid, router):
        self.log.info(format="Dropping User", code=101,
                      uaid_hash=hasher(uaid.hex))
        if not router.drop_user(uaid.hex):
            raise ItemNotFound("UAID not found")

    def _register_channel(self, router_data=None):
        self.ap_settings.message.register_channel(self.uaid.hex,
                                                  self.chid)
        endpoint = self.ap_settings.make_endpoint(self.uaid.hex,
                                                  self.chid,
                                                  self.app_server_key)
        return endpoint, router_data

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
        self._write_response(410, errno=106, message="Invalid endpoint.")

    #############################################################
    #                    Callbacks
    #############################################################
    def _save_router_data(self, router_data, router_type):
        """Called when new data needs to be saved to a user-record"""
        user_item = dict(
            uaid=self.uaid.hex,
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
                                       self.uaid.hex)
            msg = dict(
                uaid=self.uaid.hex,
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

    def base_tags(self):
        tags = list(self._base_tags)
        tags.append("user_agent:%s" %
                    self.request.headers.get("user-agent"))
        tags.append("host:%s" % self.request.host)
        return tags
