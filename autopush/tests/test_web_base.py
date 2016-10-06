import sys
import uuid

from boto.exception import BotoServerError
from cyclone.web import Application
from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.internet.defer import Deferred
from twisted.logger import Logger
from twisted.python.failure import Failure
from twisted.trial import unittest

from autopush.db import (
    create_rotating_message_table,
    ProvisionedThroughputExceededException,
)
from autopush.exceptions import InvalidRequest
from autopush.settings import AutopushSettings

dummy_request_id = "11111111-1234-1234-1234-567812345678"
dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))
mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()
    create_rotating_message_table()


def tearDown():
    mock_dynamodb2.stop()


class TestBase(unittest.TestCase):
    CORS_METHODS = "POST,PUT"
    CORS_HEADERS = ','.join(
        ["content-encoding", "encryption",
         "crypto-key", "ttl",
         "encryption-key", "content-type",
         "authorization"]
    )
    CORS_RESPONSE_HEADERS = ','.join(
        ["location", "www-authenticate"]
    )

    def setUp(self):
        from autopush.web.base import BaseWebHandler

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )

        self.request_mock = Mock(body=b'', arguments={},
                                 headers={"ttl": "0"},
                                 host='example.com:8080')

        self.base = BaseWebHandler(Application(),
                                   self.request_mock,
                                   ap_settings=settings)
        self.status_mock = self.base.set_status = Mock()
        self.write_mock = self.base.write = Mock()
        self.base.log = Mock(spec=Logger)
        d = self.finish_deferred = Deferred()
        self.base.finish = lambda: d.callback(True)

        # Attach some common cors stuff for testing
        self.base.cors_methods = "POST,PUT"
        self.base.cors_request_headers = ["content-encoding", "encryption",
                                          "crypto-key", "ttl",
                                          "encryption-key", "content-type",
                                          "authorization"]
        self.base.cors_response_headers = ["location", "www-authenticate"]

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        base = self.base
        base.ap_settings.cors = False
        ok_(base._headers.get(ch1) != "*")
        ok_(base._headers.get(ch2) != self.CORS_METHODS)
        ok_(base._headers.get(ch3) != self.CORS_HEADERS)
        ok_(base._headers.get(ch4) != self.CORS_RESPONSE_HEADERS)

        base.clear_header(ch1)
        base.clear_header(ch2)
        base.ap_settings.cors = True
        self.base.prepare()
        eq_(base._headers[ch1], "*")
        eq_(base._headers[ch2], self.CORS_METHODS)
        eq_(base._headers[ch3], self.CORS_HEADERS)
        eq_(base._headers[ch4], self.CORS_RESPONSE_HEADERS)

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        base = self.base
        base.ap_settings.cors = True
        base.prepare()
        args = {"api_ver": "v1", "token": "test"}
        base.head(args)
        eq_(base._headers[ch1], "*")
        eq_(base._headers[ch2], self.CORS_METHODS)
        eq_(base._headers[ch3], self.CORS_HEADERS)
        eq_(base._headers[ch4], self.CORS_RESPONSE_HEADERS)

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        # These should match the full endpoint arguments specified in
        # autopush.main.endpoint_main
        args = {"api_ver": "v1", "token": "test"}
        base = self.base
        base.ap_settings.cors = True
        base.prepare()
        base.options(args)
        eq_(base._headers[ch1], "*")
        eq_(base._headers[ch2], self.CORS_METHODS)
        eq_(base._headers[ch3], self.CORS_HEADERS)
        eq_(base._headers[ch4], self.CORS_RESPONSE_HEADERS)

    def test_write_error(self):
        """ Write error is triggered by sending the app a request
        with an invalid method (e.g. "put" instead of "PUT").
        This is not code that is triggered within normal flow, but
        by the cyclone wrapper.
        """
        class TestX(Exception):
            pass

        try:
            raise TestX()
        except:
            exc_info = sys.exc_info()

        self.base.write_error(999, exc_info=exc_info)
        self.status_mock.assert_called_with(999)
        eq_(self.base.log.failure.called, True)

    def test_write_error_no_exc(self):
        """ Write error is triggered by sending the app a request
        with an invalid method (e.g. "put" instead of "PUT").
        This is not code that is triggered within normal flow, but
        by the cyclone wrapper.
        """
        self.base.write_error(999)
        self.status_mock.assert_called_with(999)
        eq_(self.base.log.failure.called, True)

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_request_id))
    def test_init_info(self, t):
        h = self.request_mock.headers
        h["user-agent"] = "myself"
        self.request_mock.remote_ip = "local1"
        self.request_mock.headers["ttl"] = "0"
        self.request_mock.headers["authorization"] = "bearer token fred"
        d = self.base._init_info()
        eq_(d["request_id"], dummy_request_id)
        eq_(d["user_agent"], "myself")
        eq_(d["remote_ip"], "local1")
        eq_(d["message_ttl"], "0")
        eq_(d["authorization"], "bearer token fred")
        self.request_mock.headers["x-forwarded-for"] = "local2"
        self.request_mock.headers["authorization"] = "webpush token barney"
        d = self.base._init_info()
        eq_(d["remote_ip"], "local2")
        eq_(d["authorization"], "webpush token barney")

    def test_write_response(self):
        self.base._write_response(400, 103, message="Fail",
                                  headers=dict(Location="http://a.com/"))
        self.status_mock.assert_called_with(400, reason=None)

    def test_validation_error(self):
        try:
            raise InvalidRequest("oops", errno=110)
        except InvalidRequest:
            fail = Failure()
        self.base._validation_err(fail)
        self.status_mock.assert_called_with(400, reason=None)

    def test_response_err(self):
        try:
            raise Exception("oops")
        except Exception:
            fail = Failure()
        self.base._response_err(fail)
        self.status_mock.assert_called_with(500, reason=None)

    def test_overload_err(self):
        try:
            raise ProvisionedThroughputExceededException("error", None, None)
        except ProvisionedThroughputExceededException:
            fail = Failure()
        self.base._overload_err(fail)
        self.status_mock.assert_called_with(503, reason=None)

    def test_boto_err(self):
        try:
            raise BotoServerError(503, "derp")
        except BotoServerError:
            fail = Failure()
        self.base._boto_err(fail)
        self.status_mock.assert_called_with(503, reason=None)

    def test_router_response(self):
        from autopush.router.interface import RouterResponse
        response = RouterResponse(headers=dict(Location="http://a.com/"))
        self.base._router_response(response)
        self.status_mock.assert_called_with(200, reason=None)

    def test_router_response_client_error(self):
        from autopush.router.interface import RouterResponse
        response = RouterResponse(headers=dict(Location="http://a.com/"),
                                  status_code=400)
        self.base._router_response(response)
        self.status_mock.assert_called_with(400, reason=None)

    def test_router_fail_err(self):
        from autopush.exceptions import RouterException

        try:
            raise RouterException("error")
        except RouterException:
            fail = Failure()
        self.base._router_fail_err(fail)
        self.status_mock.assert_called_with(500, reason=None)

    def test_router_fail_err_200_status(self):
        from autopush.exceptions import RouterException

        try:
            raise RouterException("Abort Ok", status_code=200)
        except RouterException:
            fail = Failure()
        self.base._router_fail_err(fail)
        self.status_mock.assert_called_with(200, reason=None)

    def test_router_fail_err_400_status(self):
        from autopush.exceptions import RouterException

        try:
            raise RouterException("Abort Ok", status_code=400)
        except RouterException:
            fail = Failure()
        self.base._router_fail_err(fail)
        self.status_mock.assert_called_with(400, reason=None)

    def test_write_validation_err(self):
        errors = dict(data="Value too large")
        self.base._write_validation_err(errors)
        self.status_mock.assert_called_with(400, reason=None)
