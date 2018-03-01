import sys
import uuid

from botocore.exceptions import ClientError
from mock import Mock, patch
from twisted.internet.defer import Deferred
from twisted.logger import Logger
from twisted.python.failure import Failure
from twisted.trial import unittest

from autopush.config import AutopushConfig
from autopush.http import EndpointHTTPFactory
from autopush.exceptions import InvalidRequest
from autopush.metrics import SinkMetrics
from autopush.tests.support import test_db

dummy_request_id = "11111111-1234-1234-1234-567812345678"
dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))


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

        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )

        self.request_mock = Mock(body=b'', arguments={},
                                 headers={"ttl": "0"},
                                 host='example.com:8080')

        self.base = BaseWebHandler(
            EndpointHTTPFactory(conf, db=test_db(SinkMetrics()), routers=None),
            self.request_mock
        )
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
        base.conf.cors = False
        assert base._headers.get(ch1) != "*"
        assert base._headers.get(ch2) != self.CORS_METHODS
        assert base._headers.get(ch3) != self.CORS_HEADERS
        assert base._headers.get(ch4) != self.CORS_RESPONSE_HEADERS

        base.clear_header(ch1)
        base.clear_header(ch2)
        base.conf.cors = True
        self.base.prepare()
        assert base._headers[ch1] == "*"
        assert base._headers[ch2] == self.CORS_METHODS
        assert base._headers[ch3] == self.CORS_HEADERS
        assert base._headers[ch4] == self.CORS_RESPONSE_HEADERS

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        base = self.base
        base.conf.cors = True
        base.prepare()
        args = {"api_ver": "v1", "token": "test"}
        base.head(args)
        assert base._headers[ch1] == "*"
        assert base._headers[ch2] == self.CORS_METHODS
        assert base._headers[ch3] == self.CORS_HEADERS
        assert base._headers[ch4] == self.CORS_RESPONSE_HEADERS

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        # These should match the full endpoint arguments specified in
        # autopush.main.endpoint_main
        args = {"api_ver": "v1", "token": "test"}
        base = self.base
        base.conf.cors = True
        base.prepare()
        base.options(args)
        assert base._headers[ch1] == "*"
        assert base._headers[ch2] == self.CORS_METHODS
        assert base._headers[ch3] == self.CORS_HEADERS
        assert base._headers[ch4] == self.CORS_RESPONSE_HEADERS

    def test_sts_max_age_header(self):
        args = {"api_ver": "v1", "token": "test"}
        base = self.base
        base.conf.sts_max_age = 86400
        base.prepare()
        base.options(args)
        sts_header = base._headers.get("Strict-Transport-Security")
        assert "max-age=86400" in sts_header
        assert "includeSubDomains" in sts_header

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
        except Exception:
            exc_info = sys.exc_info()

        self.base.write_error(999, exc_info=exc_info)
        self.status_mock.assert_called_with(999)
        assert self.base.log.failure.called is True

    def test_write_error_no_exc(self):
        """ Write error is triggered by sending the app a request
        with an invalid method (e.g. "put" instead of "PUT").
        This is not code that is triggered within normal flow, but
        by the cyclone wrapper.
        """
        self.base.write_error(999)
        self.status_mock.assert_called_with(999)
        assert self.base.log.failure.called is True

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_request_id))
    def test_init_info(self, t):
        h = self.request_mock.headers
        h["user-agent"] = "myself"
        self.request_mock.remote_ip = "local1"
        self.request_mock.headers["ttl"] = "0"
        self.request_mock.headers["authorization"] = "bearer token fred"
        d = self.base._init_info()
        assert d["request_id"] == dummy_request_id
        assert d["user_agent"] == "myself"
        assert d["remote_ip"] == "local1"
        assert d["message_ttl"] == "0"
        assert d["authorization"] == "bearer token fred"
        self.request_mock.headers["x-forwarded-for"] = "local2"
        self.request_mock.headers["authorization"] = "webpush token barney"
        d = self.base._init_info()
        assert d["remote_ip"] == "local2"
        assert d["authorization"] == "webpush token barney"

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

    def test_connection_err(self):
        from twisted.internet.error import ConnectionDone
        try:
            raise ConnectionDone("Connection was closed cleanly.")
        except Exception:
            fail = Failure()
        self.base._response_err(fail)
        assert not self.status_mock.called

    def test_boto_err_overload(self):
        try:
            raise ClientError(
                {'Error': {
                    'Code': 'ProvisionedThroughputExceededException'}},
                'mock_update_item'
            )
        except ClientError:
            fail = Failure()
        self.base._boto_err(fail)
        self.status_mock.assert_called_with(503, reason=None)

    def test_boto_err_random(self):
        try:
            raise ClientError(
                {'Error': {
                    'Code': 'Flibbertygidgit'}},
                'mock_update_item'
            )
        except ClientError:
            fail = Failure()
        self.base._boto_err(fail)
        self.status_mock.assert_called_with(503, reason=None)

    def test_router_response(self):
        from autopush.router.interface import RouterResponse
        response = RouterResponse(headers=dict(Location="http://a.com/"))
        self.base._router_response(response, None, None)
        self.status_mock.assert_called_with(200, reason=None)

    def test_router_response_client_error(self):
        from autopush.router.interface import RouterResponse
        response = RouterResponse(headers=dict(Location="http://a.com/"),
                                  status_code=400)
        self.base._router_response(response, None, None)
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
