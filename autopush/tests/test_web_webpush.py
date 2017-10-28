import base64
import uuid

from cryptography.fernet import Fernet
from mock import Mock
from twisted.internet.defer import inlineCallbacks
from twisted.trial import unittest

from autopush.config import AutopushConfig
from autopush.db import Message
from autopush.http import EndpointHTTPFactory
from autopush.router.interface import IRouter, RouterResponse
from autopush.tests.client import Client
from autopush.tests.support import test_db

dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))
dummy_token = dummy_uaid + ":" + dummy_chid


class TestWebpushHandler(unittest.TestCase):
    def setUp(self):
        from autopush.web.webpush import WebPushHandler

        self.conf = conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
            use_cryptography=True,
        )
        self.fernet_mock = conf.fernet = Mock(spec=Fernet)

        self.db = db = test_db()
        self.message_mock = db.message = Mock(spec=Message)
        self.message_mock.all_channels.return_value = (True, [dummy_chid])

        app = EndpointHTTPFactory.for_handler(WebPushHandler, conf, db=db)
        self.wp_router_mock = app.routers["webpush"] = Mock(spec=IRouter)
        self.client = Client(app)

    def url(self, **kwargs):
        return '/wpush/{api_ver}/{token}'.format(**kwargs)

    @inlineCallbacks
    def test_router_needs_update(self):
        self.conf.parse_endpoint = Mock(return_value=dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="asdfasdf",
        ))
        self.fernet_mock.decrypt.return_value = dummy_token
        self.db.router.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
            uaid=dummy_uaid,
            current_month=self.db.current_msg_month,
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=503,
            router_data=dict(token="new_connect"),
        )

        resp = yield self.client.post(
            self.url(api_ver="v1", token=dummy_token),
        )
        assert resp.get_status() == 503
        ru = self.db.router.register_user
        assert ru.called
        assert 'webpush' == ru.call_args[0][0].get('router_type')

    @inlineCallbacks
    def test_router_returns_data_without_detail(self):
        self.conf.parse_endpoint = Mock(return_value=dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="asdfasdf",
        ))
        self.fernet_mock.decrypt.return_value = dummy_token
        self.db.router.get_uaid.return_value = dict(
            uaid=dummy_uaid,
            router_type="webpush",
            router_data=dict(uaid="uaid"),
            current_month=self.db.current_msg_month,
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=503,
            router_data=dict(),
        )

        resp = yield self.client.post(
            self.url(api_ver="v1", token=dummy_token),
        )
        assert resp.get_status() == 503
        assert self.db.router.drop_user.called

    @inlineCallbacks
    def test_request_bad_ckey(self):
        self.fernet_mock.decrypt.return_value = 'invalid key'
        resp = yield self.client.post(
            self.url(api_ver="v1", token='ignored'),
            headers={'crypto-key': 'dummy_key'}
        )
        assert resp.get_status() == 404

    @inlineCallbacks
    def test_request_bad_v1_id(self):
        self.fernet_mock.decrypt.return_value = 'tooshort'
        resp = yield self.client.post(
            self.url(api_ver="v1", token='ignored'),
        )
        assert resp.get_status() == 404

    @inlineCallbacks
    def test_request_bad_v2_id_short(self):
        self.fernet_mock.decrypt.return_value = 'tooshort'
        resp = yield self.client.post(
            self.url(api_ver='v2', token='ignored'),
            headers={'authorization': 'vapid t=dummy_key,k=aaa'}
        )
        assert resp.get_status() == 404

    @inlineCallbacks
    def test_request_bad_draft02_auth(self):
        resp = yield self.client.post(
            self.url(api_ver='v2', token='ignored'),
            headers={'authorization': 'vapid foo'}
        )
        assert resp.get_status() == 401

    @inlineCallbacks
    def test_request_bad_draft02_missing_key(self):
        self.fernet_mock.decrypt.return_value = 'a' * 64
        resp = yield self.client.post(
            self.url(api_ver='v2', token='ignored'),
            headers={'authorization': 'vapid t=dummy.key.value,k='}
        )
        assert resp.get_status() == 401

    @inlineCallbacks
    def test_request_bad_draft02_bad_pubkey(self):
        self.fernet_mock.decrypt.return_value = 'a' * 64
        resp = yield self.client.post(
            self.url(api_ver='v2', token='ignored'),
            headers={'authorization': 'vapid t=dummy.key.value,k=!aaa'}
        )
        assert resp.get_status() == 401

    @inlineCallbacks
    def test_request_bad_v2_id_missing_pubkey(self):
        self.fernet_mock.decrypt.return_value = 'a' * 64
        resp = yield self.client.post(
            self.url(api_ver='v2', token='ignored'),
            headers={'crypto-key': 'key_id=dummy_key',
                     'authorization': 'dummy_key'}
        )
        assert resp.get_status() == 401

    @inlineCallbacks
    def test_request_v2_id_variant_pubkey(self):
        self.fernet_mock.decrypt.return_value = 'a' * 32
        variant_key = base64.urlsafe_b64encode("0V0" + ('a' * 85))
        self.db.router.get_uaid.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        resp = yield self.client.post(
            self.url(api_ver='v1', token='ignored'),
            headers={'crypto-key': 'p256ecdsa=' + variant_key,
                     'authorization': 'webpush dummy.key'}
        )
        assert resp.get_status() == 401

    @inlineCallbacks
    def test_request_v2_id_no_crypt_auth(self):
        self.fernet_mock.decrypt.return_value = 'a' * 32
        self.db.router.get_uaid.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        resp = yield self.client.post(
            self.url(api_ver='v1', token='ignored'),
            headers={'authorization': 'webpush dummy.key'}
        )
        assert resp.get_status() == 401

    @inlineCallbacks
    def test_request_no_router_type(self):
        self.fernet_mock.decrypt.return_value = 'a' * 32
        self.db.router.get_uaid.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
        )
        resp = yield self.client.post(
            self.url(api_ver='v1', token='ignored'),
            headers={'authorization': 'webpush dummy.key'}
        )
        assert resp.get_status() == 410

    @inlineCallbacks
    def test_request_bad_v2_id_bad_pubkey(self):
        self.fernet_mock.decrypt.return_value = 'a' * 64
        resp = yield self.client.post(
            self.url(api_ver='v2', token='ignored'),
            headers={'crypto-key': 'p256ecdsa=Invalid!',
                     'authorization': 'dummy_key'}
        )
        assert resp.get_status() == 401
