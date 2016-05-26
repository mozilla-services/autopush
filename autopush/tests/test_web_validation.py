import uuid

from boto.dynamodb2.exceptions import (
    ItemNotFound,
)
from marshmallow import Schema, fields
from mock import Mock
from nose.tools import eq_, ok_, assert_raises
from twisted.internet.defer import Deferred
from twisted.trial import unittest

from autopush.exceptions import (
    InvalidRequest,
    InvalidTokenException,
)


dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))
dummy_token = dummy_uaid + ":" + dummy_chid


class InvalidSchema(Schema):
    afield = fields.Integer(required=True)


class TestThreadedValidate(unittest.TestCase):
    def _makeFUT(self, schema):
        from autopush.web.validation import ThreadedValidate
        return ThreadedValidate(schema)

    def _makeBasicSchema(self):

        class Basic(Schema):
            pass

        return Basic()

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
        tv, rh = self._makeFull(schema=InvalidSchema())
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
        tv, rh = self._makeFull(schema=InvalidSchema())
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
