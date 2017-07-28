import time
import uuid

from hashlib import sha256

import ecdsa
from boto.dynamodb2.exceptions import (
    ItemNotFound,
)
from cryptography.fernet import InvalidToken
from cryptography.exceptions import InvalidSignature
from jose import jws
from marshmallow import Schema, fields
from mock import Mock, patch
from nose.tools import eq_, ok_, assert_raises
from twisted.internet.defer import inlineCallbacks
from twisted.trial import unittest

from autopush.metrics import SinkMetrics
from autopush.exceptions import InvalidRequest, InvalidTokenException
from autopush.tests.support import test_db
import autopush.utils as utils


dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))
dummy_token = dummy_uaid + ":" + dummy_chid


class InvalidSchema(Schema):
    afield = fields.Integer(required=True)


class TestThreadedValidate(unittest.TestCase):
    def _make_fut(self, schema):
        from autopush.web.base import ThreadedValidate
        return ThreadedValidate(schema)

    def _make_basic_schema(self):

        class Basic(Schema):
            pass

        return Basic

    def _make_dummy_request(self, method="GET", uri="/", **kwargs):
        from cyclone.httpserver import HTTPRequest
        req = HTTPRequest(method, uri, **kwargs)
        req.connection = Mock()
        return req

    def _make_req_handler(self, request):
        self._mock_errors = Mock()
        from cyclone.web import RequestHandler

        class ValidateRequest(RequestHandler):
            def _write_validation_err(rh, errors):
                self._mock_errors(errors)

        # Minimal mocks needed for a cyclone app to work
        app = Mock()
        app.ui_modules = dict()
        app.ui_methods = dict()
        vr = ValidateRequest(app, request)
        vr._timings = dict()
        vr.ap_settings = Mock()
        vr.metrics = Mock()
        vr.db = Mock()
        vr.routers = Mock()
        return vr

    def _make_full(self, schema=None):
        req = self._make_dummy_request()
        if not schema:
            schema = self._make_basic_schema()
        tv = self._make_fut(schema)
        rh = self._make_req_handler(req)

        return tv, rh

    def test_validate_load(self):
        tv, rh = self._make_full()
        d, errors = tv._validate_request(rh)
        eq_(errors, {})
        eq_(d, {})

    def test_validate_invalid_schema(self):
        tv, rh = self._make_full(schema=InvalidSchema)
        d, errors = tv._validate_request(rh)
        ok_("afield" in errors)
        eq_(d, {})

    def test_call_func_no_error(self):
        mock_func = Mock()
        tv, rh = self._make_full()
        result = tv._validate_request(rh)
        tv._call_func(result, mock_func, rh)
        mock_func.assert_called()

    def test_call_func_error(self):
        mock_func = Mock()
        tv, rh = self._make_full(schema=InvalidSchema)
        result = tv._validate_request(rh)
        tv._call_func(result, mock_func, rh)
        self._mock_errors.assert_called()
        eq_(len(mock_func.mock_calls), 0)

    @inlineCallbacks
    def test_decorator(self):
        from autopush.http import EndpointHTTPFactory
        from autopush.web.base import BaseWebHandler, threaded_validate
        from autopush.tests.client import Client
        schema = self._make_basic_schema()

        class AHandler(BaseWebHandler):
            def authenticate_peer_cert(self):
                pass

            @threaded_validate(schema)
            def get(self):
                self.write("done")
                self.finish()

        app = EndpointHTTPFactory(
            Mock(),
            db=test_db(),
            routers=None,
            handlers=[('/test', AHandler)]
        )
        client = Client(app)
        resp = yield client.get('/test')
        eq_(resp.content, "done")


class TestSimplePushRequestSchema(unittest.TestCase):
    def _make_fut(self):
        from autopush.web.simplepush import SimplePushRequestSchema
        schema = SimplePushRequestSchema()
        schema.context.update(
            settings=Mock(),
            metrics=SinkMetrics(),
            db=test_db(),
            routers=Mock(),
            log=Mock()
        )
        return schema

    def _make_test_data(self, headers=None, body="", path_args=None,
                        path_kwargs=None, arguments=None):
        return dict(
            headers=headers or {},
            body=body,
            path_args=path_args or [],
            path_kwargs=path_kwargs or {},
            arguments=arguments or {},
        )

    def test_valid_data(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )
        result, errors = schema.load(self._make_test_data())
        eq_(errors, {})
        eq_(result["data"], None)
        eq_(str(result["subscription"]["uaid"]), dummy_uaid)

    def test_valid_data_in_body(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )
        result, errors = schema.load(
            self._make_test_data(body="version=&data=asdfasdf")
        )
        eq_(errors, {})
        eq_(result["data"], "asdfasdf")
        eq_(str(result["subscription"]["uaid"]), dummy_uaid)

    def test_valid_version(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )
        result, errors = schema.load(
            self._make_test_data(body="version=3&data=asdfasdf")
        )
        eq_(errors, {})
        eq_(result["data"], "asdfasdf")
        eq_(result["version"], 3)
        eq_(str(result["subscription"]["uaid"]), dummy_uaid)

    def test_invalid_router_type(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 108)

    def test_invalid_uaid_not_found(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )

        def throw_item(*args, **kwargs):
            raise ItemNotFound("Not found")

        schema.context["db"].router.get_uaid.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 103)

    def test_invalid_token(self):
        schema = self._make_fut()

        def throw_item(*args, **kwargs):
            raise InvalidTokenException("Not found")

        schema.context["settings"].parse_endpoint.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 102)

    def test_invalid_data_size(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )
        schema.context["settings"].max_data = 1

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data(body="version=&data=asdfasdf"))

        eq_(cm.exception.errno, 104)


class TestWebPushRequestSchema(unittest.TestCase):
    def _make_fut(self):
        from autopush.web.webpush import WebPushRequestSchema
        schema = WebPushRequestSchema()
        schema.context.update(
            settings=Mock(),
            metrics=SinkMetrics(),
            db=test_db(),
            routers=Mock(),
            log=Mock()
        )
        return schema

    def _make_test_data(self, headers=None, body="", path_args=None,
                        path_kwargs=None, arguments=None):
        return dict(
            headers=headers or {},
            body=body,
            path_args=path_args or [],
            path_kwargs=path_kwargs or {},
            arguments=arguments or {},
        )

    def test_valid_data(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        result, errors = schema.load(self._make_test_data())
        eq_(errors, {})
        ok_("notification" in result)
        eq_(str(result["subscription"]["uaid"]), dummy_uaid)

    def test_no_headers(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        data = self._make_test_data(body="asdfasdf")

        with assert_raises(InvalidRequest) as cm:
            schema.load(data)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 110)
        eq_(cm.exception.message, "Unknown Content-Encoding")

    def test_invalid_simplepush_user(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 108)

    def test_invalid_token(self):
        schema = self._make_fut()

        def throw_item(*args, **kwargs):
            raise InvalidTokenException("Not found")

        schema.context["settings"].parse_endpoint.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 102)

    def test_invalid_fernet_token(self):
        schema = self._make_fut()

        def throw_item(*args, **kwargs):
            raise InvalidToken

        schema.context["settings"].parse_endpoint.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 102)

    def test_invalid_uaid_not_found(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )

        def throw_item(*args, **kwargs):
            raise ItemNotFound("Not found")

        schema.context["db"].router.get_uaid.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 103)

    def test_critical_failure(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="fcm",
            critical_failure="Bad SenderID",
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 105)

    def test_invalid_header_combo(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        info = self._make_test_data(
            headers={
                "content-encoding": "aesgcm128",
                "crypto-key": "dh=asdfjialsjdfiasjld",
                "encryption-key": "dh=asdfjasidlfjaislf",
            },
            body="asdfasdf",
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.errno, 110)

    def test_invalid_header_combo_04(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        info = self._make_test_data(
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=ajisldjfi",
                "crypto-key": "dh=asdfjialsjdfiasjld",
                "encryption-key": "dh=asdfjasidlfjaislf",
            },
            body="asdfasdf",
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.message, "Encryption-Key header not valid for 02 "
                                  "or later webpush-encryption")
        eq_(cm.exception.errno, 110)

    def test_missing_encryption_salt(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        info = self._make_test_data(
            headers={
                "content-encoding": "aesgcm128",
                "encryption": "dh=asdfjasidlfjaislf",
                "encryption-key": "dh=jilajsidfljasildjf",
            },
            body="asdfasdf",
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 110)

    def test_missing_encryption_salt_04(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        info = self._make_test_data(
            headers={
                "content-encoding": "aesgcm",
                "encryption": "dh=asdfjasidlfjaislf",
                "crypto-key": "dh=jilajsidfljasildjf",
            },
            body="asdfasdf",
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 110)

    def test_missing_encryption_key_dh(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )
        info = self._make_test_data(
            headers={
                "content-encoding": "aesgcm128",
                "encryption": "salt=asdfjasidlfjaislf",
                "encryption-key": "keyid=jialsjdifjlasd",
            },
            body="asdfasdf",
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 110)

    def test_missing_crypto_key_dh(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            uaid=dummy_uaid,
            router_data=dict(creds=dict(senderID="bogus")),
        )
        info = self._make_test_data(
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=asdfjasidlfjaislf",
                "crypto-key": "p256ecdsa=BA1Hxzyi1RUM1b5wjxsn7nGxAs",
            },
            body="asdfasdf",
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 110)

    def test_invalid_data_size(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            uaid=dummy_uaid,
            router_data=dict(creds=dict(senderID="bogus")),
        )
        schema.context["settings"].max_data = 1

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data(
                headers={
                    "content-encoding": "aesgcm",
                    "crypto-key": "dh=asdfjialsjdfiasjld",
                },
                body="asdfasdfasdfasdfasd"))

        eq_(cm.exception.errno, 104)

    def test_invalid_data_must_have_crypto_headers(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data(body="asdfasdfasdfasdfasd"))

        eq_(cm.exception.errno, 110)

    def test_valid_data_crypto_padding_stripped(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )

        padded_value = "asdfjiasljdf==="

        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            headers={
                "content-encoding": "aesgcm128",
                "encryption": "salt=" + padded_value,
                "encryption-key": "dh=asdfasdfasdf",
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        eq_(result["headers"]["encryption"], "salt=asdfjiasljdf")

    def test_invalid_dh_value_for_01_crypto(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            router_data=dict(creds=dict(senderID="bogus")),
        )

        padded_value = "asdfjiasljdf==="

        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            headers={
                "authorization": "not vapid",
                "content-encoding": "aesgcm128",
                "encryption": "salt=" + padded_value,
                "crypto-key": "dh=asdfasdfasdf"
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.message, "dh value in Crypto-Key header not valid "
            "for 01 or earlier webpush-encryption")

    def test_invalid_vapid_crypto_header(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            uaid=dummy_uaid,
            router_data=dict(creds=dict(senderID="bogus")),
        )

        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=ignored",
                "authorization": "invalid",
                "crypto-key": "dh=crap",
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)

    def test_invalid_topic(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="gcm",
            uaid=dummy_uaid,
            router_data=dict(creds=dict(senderID="bogus")),
        )

        info = self._make_test_data(
            headers={
                "topic": "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdf",
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 113)
        eq_(cm.exception.message,
            "Topic must be no greater than 32 characters")

        info = self._make_test_data(
            headers={
                "topic": "asdf??asdf::;f",
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 113)
        eq_(cm.exception.message,
            "Topic must be URL and Filename safe Base64 alphabet")

    def test_no_current_month(self):
        schema = self._make_fut()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="webpush",
            uaid=dummy_uaid,
        )

        info = self._make_test_data()

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 410)
        eq_(cm.exception.errno, 106)
        eq_(cm.exception.message, "No such subscription")

    def test_old_current_month(self):
        schema = self._make_fut()
        schema.context["db"].message_tables = dict()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["db"].router.get_uaid.return_value = dict(
            router_type="webpush",
            uaid=dummy_uaid,
            current_month="message_2014_01",
        )

        info = self._make_test_data()

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 410)
        eq_(cm.exception.errno, 106)
        eq_(cm.exception.message, "No such subscription")


class TestWebPushRequestSchemaUsingVapid(unittest.TestCase):
    def _make_fut(self):
        from autopush.web.webpush import WebPushRequestSchema
        from autopush.settings import AutopushConfig
        settings = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        db = test_db()
        schema = WebPushRequestSchema()
        schema.context.update(
            settings=settings,
            metrics=SinkMetrics(),
            db=db,
            routers=Mock(),
            log=Mock()
        )
        db.router.get_uaid.return_value = dict(
            router_type="gcm",
            uaid=dummy_uaid,
            router_data=dict(creds=dict(senderID="bogus")),
        )
        settings.fernet = self.fernet_mock = Mock()
        return schema

    def _make_test_data(self, headers=None, body="", path_args=None,
                        path_kwargs=None, arguments=None):
        return dict(
            headers=headers or {},
            body=body,
            path_args=path_args or [],
            path_kwargs=path_kwargs or {"api_ver": "v2", "token": "xxx"},
            arguments=arguments or {},
        )

    def _gen_jwt(self, header, payload):
        sk256p = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        vk = sk256p.get_verifying_key()
        sig = jws.sign(payload, sk256p, algorithm="ES256").strip('=')
        crypto_key = utils.base64url_encode(vk.to_string()).strip('=')
        return sig, crypto_key

    def test_valid_vapid_crypto_header(self):
        schema = self._make_fut()

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "Bearer %s" % token
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        ok_("jwt" in result)

    def test_valid_vapid_crypto_header_webpush(self, use_crypto=False):
        schema = self._make_fut()
        schema.context["settings"].use_cryptography = use_crypto

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "WebPush %s" % token
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        ok_("jwt" in result)

    def test_valid_vapid_crypto_header_webpush_crypto(self):
        self.test_valid_vapid_crypto_header_webpush(use_crypto=True)

    def test_valid_vapid_02_crypto_header_webpush(self):
        schema = self._make_fut()

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "vapid t={token},k={key}".format(token=token,
                                                key=crypto_key)
        self.fernet_mock.decrypt.return_value = ('a' * 32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        ok_("jwt" in result)
        eq_(payload, result['jwt']['jwt_data'])

    def test_valid_vapid_02_crypto_header_webpush_alt(self):
        schema = self._make_fut()

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        # Switch the params and add an extra, ignored parameter
        auth = "vapid k={key},  t={token},   foo=bar".format(
            token=token,
            key=crypto_key)
        self.fernet_mock.decrypt.return_value = ('a' * 32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        ok_("jwt" in result)
        eq_(payload, result['jwt']['jwt_data'])

    def test_bad_vapid_02_crypto_header(self):
        schema = self._make_fut()

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        # Missing one of the two required parameters, t & k
        auth = "vapid t={token},n={key}".format(token=token,
                                                key=crypto_key)
        self.fernet_mock.decrypt.return_value = ('a' * 32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)
        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    def test_invalid_vapid_draft2_crypto_header(self):
        schema = self._make_fut()
        schema.context["settings"].use_cryptography = True

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        # Corrupt the token so it fails. (Mock doesn't always catch)
        auth = "vapid t={token},k={key}".format(token=token+"foo",
                                                key=crypto_key)
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    @patch("autopush.web.webpush.extract_jwt")
    def test_invalid_vapid_crypto_header(self, mock_jwt):
        schema = self._make_fut()
        schema.context["settings"].use_cryptography = True

        mock_jwt.side_effect = ValueError("Unknown public key "
                                          "format specified")

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        auth = "WebPush %s" % token
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    def test_invalid_too_far_exp_vapid_crypto_header(self):
        schema = self._make_fut()
        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400 + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "WebPush %s" % token
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    def test_invalid_bad_exp_vapid_crypto_header(self):
        schema = self._make_fut()
        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": "bleh",
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "WebPush %s" % token
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    @patch("autopush.web.webpush.extract_jwt")
    def test_invalid_encryption_header(self, mock_jwt):
        schema = self._make_fut()
        mock_jwt.side_effect = ValueError("Unknown public key "
                                          "format specified")

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        auth = "Bearer %s" % token
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    @patch("autopush.web.webpush.extract_jwt")
    def test_invalid_encryption_jwt(self, mock_jwt):
        schema = self._make_fut()
        schema.context['settings'].use_cryptography = True
        # use a deeply superclassed error to make sure that it gets picked up.
        mock_jwt.side_effect = InvalidSignature("invalid signature")

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://push.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        auth = "Bearer %s" % token
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    @patch("autopush.web.webpush.extract_jwt")
    def test_invalid_crypto_key_header_content(self, mock_jwt):
        schema = self._make_fut()
        mock_jwt.side_effect = ValueError("Unknown public key "
                                          "format specified")

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        auth = "Bearer %s" % token
        ckey = 'keyid="a1";invalid="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aes128",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 400)
        eq_(cm.exception.errno, 110)

    def test_expired_vapid_header(self):
        schema = self._make_fut()
        schema.context["settings"].use_cryptography = True

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": 20,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "WebPush %s" % token
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    def test_missing_vapid_header(self):
        schema = self._make_fut()

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {
            "aud": "https://pusher_origin.example.com",
            "exp": 20,
            "sub": "mailto:admin@example.com"
            }

        token, crypto_key = self._gen_jwt(header, payload)
        self.fernet_mock.decrypt.return_value = ('a'*32) + \
            sha256(utils.base64url_decode(crypto_key)).digest()
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    def test_bogus_vapid_header(self):
        schema = self._make_fut()
        schema.context["settings"].use_cryptography = True

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {
            "aud": "https://pusher_origin.example.com",
            "exp": 20,
            "sub": "mailto:admin@example.com"
        }

        token, crypto_key = self._gen_jwt(header, payload)
        self.fernet_mock.decrypt.return_value = (
            'a' * 32) + sha256(utils.base64url_decode(crypto_key)).digest()
        ckey = 'keyid="a1"; dh="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v2",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aesgcm",
                "encryption": "salt=stuff",
                "crypto-key": ckey,
                "authorization": "bogus crap"
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)
