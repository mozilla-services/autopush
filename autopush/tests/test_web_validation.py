import time
import uuid

import ecdsa
from boto.dynamodb2.exceptions import (
    ItemNotFound,
)
from cryptography.fernet import InvalidToken
from jose import jws
from marshmallow import Schema, fields
from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_, ok_, assert_raises
from twisted.internet.defer import Deferred
from twisted.trial import unittest

from autopush.db import (
    create_rotating_message_table,
)
from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
)
import autopush.utils as utils


dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))
dummy_token = dummy_uaid + ":" + dummy_chid
mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()
    create_rotating_message_table()


def tearDown():
    mock_dynamodb2.stop()


class InvalidSchema(Schema):
    afield = fields.Integer(required=True)


class TestThreadedValidate(unittest.TestCase):
    def _makeFUT(self, schema):
        from autopush.web.validation import ThreadedValidate
        return ThreadedValidate(schema)

    def _makeBasicSchema(self):

        class Basic(Schema):
            pass

        return Basic

    def _makeDummyRequest(self, method="GET", uri="/", **kwargs):
        from cyclone.httpserver import HTTPRequest
        req = HTTPRequest(method, uri, **kwargs)
        req.connection = Mock()
        return req

    def _makeReqHandler(self, request):
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
        vr.ap_settings = Mock()
        return vr

    def _makeFull(self, schema=None):
        req = self._makeDummyRequest()
        if not schema:
            schema = self._makeBasicSchema()
        tv = self._makeFUT(schema)
        rh = self._makeReqHandler(req)

        return tv, rh

    def test_validate_load(self):
        tv, rh = self._makeFull()
        d, errors = tv._validate_request(rh)
        eq_(errors, {})
        eq_(d, {})

    def test_validate_invalid_schema(self):
        tv, rh = self._makeFull(schema=InvalidSchema)
        d, errors = tv._validate_request(rh)
        ok_("afield" in errors)
        eq_(d, {})

    def test_call_func_no_error(self):
        mock_func = Mock()
        tv, rh = self._makeFull()
        result = tv._validate_request(rh)
        tv._call_func(result, mock_func, rh)
        mock_func.assert_called()

    def test_call_func_error(self):
        mock_func = Mock()
        tv, rh = self._makeFull(schema=InvalidSchema)
        result = tv._validate_request(rh)
        tv._call_func(result, mock_func, rh)
        self._mock_errors.assert_called()
        eq_(len(mock_func.mock_calls), 0)

    def test_decorator(self):
        from cyclone.web import RequestHandler
        from autopush.web.validation import threaded_validate
        schema = self._makeBasicSchema()

        class AHandler(RequestHandler):
            @threaded_validate(schema)
            def get(self):
                self.write("done")
                self.finish()

        req = self._makeDummyRequest()
        app = Mock()
        app.ui_modules = dict()
        app.ui_methods = dict()
        vr = AHandler(app, req)
        d = Deferred()
        vr.finish = lambda: d.callback(True)
        vr.write = Mock()
        vr._overload_err = Mock()
        vr._validation_err = Mock()
        vr._response_err = Mock()
        vr.ap_settings = Mock()

        e = Deferred()

        def check_result(result):
            vr.write.assert_called_with("done")
            e.callback(True)

        d.addCallback(check_result)

        vr.get()
        return e


class TestSimplePushRequestSchema(unittest.TestCase):
    def _makeFUT(self):
        from autopush.web.validation import SimplePushRequestSchema
        schema = SimplePushRequestSchema()
        schema.context["settings"] = Mock()
        schema.context["log"] = Mock()
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
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )
        result, errors = schema.load(self._make_test_data())
        eq_(errors, {})
        eq_(result["data"], None)
        eq_(str(result["subscription"]["uaid"]), dummy_uaid)

    def test_valid_data_in_body(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )
        result, errors = schema.load(
            self._make_test_data(body="version=&data=asdfasdf")
        )
        eq_(errors, {})
        eq_(result["data"], "asdfasdf")
        eq_(str(result["subscription"]["uaid"]), dummy_uaid)

    def test_valid_version(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
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
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 108)

    def test_invalid_uaid_not_found(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )

        def throw_item(*args, **kwargs):
            raise ItemNotFound("Not found")

        schema.context["settings"].router.get_uaid.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 103)

    def test_invalid_token(self):
        schema = self._makeFUT()

        def throw_item(*args, **kwargs):
            raise InvalidTokenException("Not found")

        schema.context["settings"].parse_endpoint.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 102)

    def test_invalid_data_size(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )
        schema.context["settings"].max_data = 1

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data(body="version=&data=asdfasdf"))

        eq_(cm.exception.errno, 104)


class TestWebPushRequestSchema(unittest.TestCase):
    def _makeFUT(self):
        from autopush.web.validation import WebPushRequestSchema
        schema = WebPushRequestSchema()
        schema.context["settings"] = Mock()
        schema.context["log"] = Mock()
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
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )
        result, errors = schema.load(self._make_test_data())
        eq_(errors, {})
        ok_("message_id" in result)
        eq_(str(result["subscription"]["uaid"]), dummy_uaid)

    def test_invalid_simplepush_user(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="simplepush",
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 108)

    def test_invalid_token(self):
        schema = self._makeFUT()

        def throw_item(*args, **kwargs):
            raise InvalidTokenException("Not found")

        schema.context["settings"].parse_endpoint.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 102)

    def test_invalid_fernet_token(self):
        schema = self._makeFUT()

        def throw_item(*args, **kwargs):
            raise InvalidToken

        schema.context["settings"].parse_endpoint.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 102)

    def test_invalid_uaid_not_found(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )

        def throw_item(*args, **kwargs):
            raise ItemNotFound("Not found")

        schema.context["settings"].router.get_uaid.side_effect = throw_item

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 103)

    def test_critical_failure(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="fcm",
            critical_failure="Bad SenderID",
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data())

        eq_(cm.exception.errno, 105)

    def test_invalid_header_combo(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )
        info = self._make_test_data(
            headers={
                "content-encoding": "aesgcm128",
                "crypto-key": "asdfjialsjdfiasjld",
            }
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.errno, 110)

        info = self._make_test_data(
            headers={
                "encryption-key": "aesgcm128",
                "crypto-key": "asdfjialsjdfiasjld",
            }
        )
        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.errno, 110)

    def test_invalid_data_size(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )
        schema.context["settings"].max_data = 1

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data(body="asdfasdfasdfasdfasd"))

        eq_(cm.exception.errno, 104)

    def test_invalid_data_must_have_crypto_headers(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(self._make_test_data(body="asdfasdfasdfasdfasd"))

        eq_(cm.exception.errno, 110)

    def test_valid_data_crypto_padding_stripped(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )

        padded_value = "asdfjiasljdf==="

        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            headers={
                "authorization": "not vapid",
                "content-encoding": "aesgcm128",
                "encryption": padded_value
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        eq_(result["headers"]["encryption"], "asdfjiasljdf")

    def test_invalid_vapid_crypto_header(self):
        schema = self._makeFUT()
        schema.context["settings"].parse_endpoint.return_value = dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="",
        )
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )

        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            headers={
                "content-encoding": "text",
                "encryption": "ignored",
                "authorization": "invalid",
                "crypto-key": "crypt=crap",
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)


class TestWebPushRequestSchemaUsingVapid(unittest.TestCase):
    def _makeFUT(self):
        from autopush.web.validation import WebPushRequestSchema
        from autopush.settings import AutopushSettings
        schema = WebPushRequestSchema()
        schema.context["log"] = Mock()
        schema.context["settings"] = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        schema.context["settings"].router = Mock()
        schema.context["settings"].router.get_uaid.return_value = dict(
            router_type="webpush",
        )
        schema.context["settings"].fernet = self.fernet_mock = Mock()
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

    def _gen_jwt(self, header, payload):
        sk256p = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        vk = sk256p.get_verifying_key()
        sig = jws.sign(payload, sk256p, algorithm="ES256").strip('=')
        crypto_key = utils.base64url_encode(vk.to_string()).strip('=')
        return sig, crypto_key

    def test_valid_vapid_crypto_header(self):
        schema = self._makeFUT()
        self.fernet_mock.decrypt.return_value = dummy_token

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "Bearer %s" % token
        ckey = 'keyid="a1"; key="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v0",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aes128",
                "encryption": "stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        ok_("jwt" in result)

    def test_valid_vapid_crypto_header_webpush(self):
        schema = self._makeFUT()
        self.fernet_mock.decrypt.return_value = dummy_token

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "WebPush %s" % token
        ckey = 'keyid="a1"; key="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v0",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aes128",
                "encryption": "stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        result, errors = schema.load(info)
        eq_(errors, {})
        ok_("jwt" in result)

    @patch("autopush.web.validation.extract_jwt")
    def test_invalid_vapid_crypto_header(self, mock_jwt):
        schema = self._makeFUT()
        self.fernet_mock.decrypt.return_value = dummy_token
        mock_jwt.side_effect = ValueError("Unknown public key "
                                          "format specified")

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "WebPush %s" % token
        ckey = 'keyid="a1"; key="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v0",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aes128",
                "encryption": "stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)

    def test_expired_vapid_header(self):
        schema = self._makeFUT()
        self.fernet_mock.decrypt.return_value = dummy_token

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": 20,
                   "sub": "mailto:admin@example.com"}

        token, crypto_key = self._gen_jwt(header, payload)
        auth = "WebPush %s" % token
        ckey = 'keyid="a1"; key="foo";p256ecdsa="%s"' % crypto_key
        info = self._make_test_data(
            body="asdfasdfasdfasdf",
            path_kwargs=dict(
                api_ver="v0",
                token="asdfasdf",
            ),
            headers={
                "content-encoding": "aes128",
                "encryption": "stuff",
                "authorization": auth,
                "crypto-key": ckey
            }
        )

        with assert_raises(InvalidRequest) as cm:
            schema.load(info)

        eq_(cm.exception.status_code, 401)
        eq_(cm.exception.errno, 109)
