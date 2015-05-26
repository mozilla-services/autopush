import functools
import json
import sys

import twisted.internet.base
from cryptography.fernet import Fernet, InvalidToken
from cyclone.web import Application
from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_, ok_
from StringIO import StringIO
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure
from twisted.trial import unittest
from twisted.web.client import Agent, Response, ResponseDone
from txstatsd.metrics.metrics import Metrics

import autopush.endpoint as endpoint
from autopush.db import Router, Storage
from autopush.bridge.bridge import Bridge
from autopush.settings import AutopushSettings


class FileConsumer(object):
    def __init__(self, file):
        self.file = file

    def write(self, data):
        self.file.write(data)


def patch_logger(test):
    """Replaces the Twisted error logger with a mock implementation.

    This uses Trial's ``patch()`` method instead of Mock's ``@patch``
    decorator. The latter still causes the test to print a stack trace
    and fail unless ``flushLoggedErrors()`` is called.
    """
    @functools.wraps(test)
    def wrapper(self, *args, **kwargs):
        log_mock = Mock()
        self.patch(endpoint, 'log', log_mock)
        params = args + (log_mock,)
        return test(self, *params, **kwargs)
    return wrapper


class EndpointTestCase(unittest.TestCase):
    def initialize(self):
        self.metrics = self.ap_settings.metrics

    def setUp(self):
        self.timeout = 0.5

        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()
        twisted.internet.base.DelayedCall.debug = True

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.agent_mock = settings.agent = Mock(spec=Agent)
        self.response_mock = Mock(spec=Response)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.bridge_mock = settings.bridge = Mock(spec=Bridge)

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.endpoint = endpoint.EndpointHandler(Application(),
                                                 self.request_mock,
                                                 ap_settings=settings)

        self.status_mock = self.endpoint.set_status = Mock()
        self.write_mock = self.endpoint.write = Mock()

        d = self.finish_deferred = Deferred()
        self.endpoint.finish = lambda: d.callback(True)

    def tearDown(self):
        self.mock_dynamodb2.stop()

    def test_client_info(self):
        h = self.request_mock.headers
        h["user-agent"] = "myself"
        d = self.endpoint._client_info()
        eq_(d["user-agent"], "myself")
        self.request_mock.remote_ip = "local1"
        d = self.endpoint._client_info()
        eq_(d["remote-ip"], "local1")
        self.request_mock.headers["x-forwarded-for"] = "local2"
        d = self.endpoint._client_info()
        eq_(d["remote-ip"], "local2")
        self.endpoint.uaid_hash = "faa"
        d = self.endpoint._client_info()
        eq_(d["uaid_hash"], "faa")

    def test_load_params_arguments(self):
        args = self.endpoint.request.arguments
        args['version'] = ['123']
        args['data'] = ['ohai']
        version, data = endpoint.parse_request_params(self.endpoint.request)

        eq_(version, 123)
        eq_(data, 'ohai')

    def test_load_params_body(self):
        self.endpoint.request.body = b'version=1234&data=Hello%2c%20world!'
        version, data = endpoint.parse_request_params(self.endpoint.request)

        eq_(version, 1234)
        eq_(data, 'Hello, world!')

    @patch('time.time', return_value=1257894000)
    def test_load_params_invalid_body(self, t):
        self.endpoint.request.body = b'!@#$%^&[\x0d\x0a'
        version, data = endpoint.parse_request_params(self.endpoint.request)

        eq_(version, 1257894000)
        eq_(data, None)

    @patch('time.time', return_value=1257894000)
    def test_load_params_invalid_version(self, t):
        self.endpoint.request.body = b'version=bad&data=ohai'
        version, data = endpoint.parse_request_params(self.endpoint.request)

        eq_(version, 1257894000)
        eq_(data, 'ohai')

    @patch('time.time', return_value=1257894000)
    def test_load_params_negative_version(self, t):
        self.endpoint.request.body = b'version=-1&data=ohai'
        version, data = endpoint.parse_request_params(self.endpoint.request)

        eq_(version, 1257894000)
        eq_(data, 'ohai')

    @patch('time.time', return_value=1257894000)
    def test_load_params_prefer_body(self, t):
        args = self.endpoint.request.arguments
        args['version'] = ['123']
        args['data'] = ['ohai']
        self.endpoint.request.body = b'data=bai'
        version, data = endpoint.parse_request_params(self.endpoint.request)

        eq_(version, 1257894000)
        eq_(data, 'bai')

    def test_put_data_too_large(self):
        self.endpoint.ap_settings.max_data = 3
        self.endpoint.request.body = b'version=1&data=1234'

        def handle_finish(result):
            self.endpoint.set_status.assert_called_with(401)
            self.endpoint.write.assert_called_with('Data too large')
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put('')
        return self.finish_deferred

    @patch_logger
    def test_put_token_error(self, log_mock):
        self.fernet_mock.configure_mock(**{
            'decrypt.side_effect': TypeError})
        self.endpoint.request.body = b'version=123'

        def handle_finish(value):
            self.fernet_mock.decrypt.assert_called_with(b'')
            eq_(log_mock.err.called, True)
            self._assert_error_response(value)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put('')
        return self.finish_deferred

    def test_put_token_invalid(self):
        self.fernet_mock.configure_mock(**{
            'decrypt.side_effect': InvalidToken})
        self.endpoint.request.body = b'version=123&data=bad-token'

        def handle_finish(result):
            self.status_mock.assert_called_with(401)
            self.write_mock.assert_called_with('Invalid token')
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put('')
        return self.finish_deferred

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = False
        endpoint._addCors()
        assert endpoint._headers.get(ch1) != "*"
        assert endpoint._headers.get(ch2) != "PUT"

        endpoint.clear_header(ch1)
        endpoint.clear_header(ch2)
        endpoint.ap_settings.cors = True
        endpoint._addCors()
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], "PUT")

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = True
        endpoint.prepare()
        endpoint.head(None)
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], "PUT")

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = True
        endpoint.prepare()
        endpoint.options(None)
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], "PUT")

    @patch_logger
    def test_write_error(self, log_mock):
        """ Write error is triggered by sending the app a request
        with an invalid method (e.g. "put" instead of "PUT").
        This is not code that is triggered within normal flow, but
        by the cyclone wrapper. """
        class testX(Exception):
            pass

        try:
            raise testX()
        except:
            exc_info = sys.exc_info()

        self.endpoint.write_error(999, exc_info=exc_info)
        self.status_mock.assert_called_with(999)
        self.assertTrue(log_mock.err.called)

    @patch_logger
    def test_write_error_no_exc(self, log_mock):
        """ Write error is triggered by sending the app a request
        with an invalid method (e.g. "put" instead of "PUT").
        This is not code that is triggered within normal flow, but
        by the cyclone wrapper. """
        self.endpoint.write_error(999)
        self.status_mock.assert_called_with(999)
        self.assertTrue(log_mock.err.called)

    def _assert_push_request(self, expected_url, expected_body=None):
        calls = self.agent_mock.request.mock_calls
        eq_(len(calls) >= 1, True)
        _, (method, actual_url), params = calls[0]
        eq_(method, 'PUT')
        eq_(actual_url, expected_url)
        eq_('bodyProducer' in params, True)

        if not expected_body:
            return None

        request_body = StringIO()
        consumer = FileConsumer(request_body)

        producer = params.get('bodyProducer')
        if not producer:
            raise Exception('Missing body')

        def handle_body(result):
            eq_(json.loads(request_body.getvalue()), expected_body)
            return None
        d = producer.startProducing(consumer)
        d.addCallback(handle_body)
        return d

    def _assert_error_response(self, result):
        self.status_mock.assert_called_with(500)
        self.write_mock.assert_called_with("Error processing request")

    def _assert_throughput_exceeded_response(self):
        self.status_mock.assert_called_with(503)
        self.write_mock.assert_called_with('Server busy, try later')

    def _assert_miss_response(self):
        self.metrics_mock.increment.assert_called_with('router.broadcast.miss')
        self.write_mock.assert_called_with('Success')

    def _configure_agent_mock(self, code, reason=ResponseDone()):
        def deliver_body(protocol):
            protocol.dataReceived('Fake response')
            protocol.connectionLost(Failure(reason))

        def handle_request(method, url, **kwargs):
            eq_(isinstance(url, unicode), False)
            d = Deferred()
            self.response_mock.configure_mock(**{
                'code': code(url) if callable(code) else code,
                'deliverBody.side_effect': deliver_body
            })
            d.callback(self.response_mock)
            return d
        self.agent_mock.configure_mock(**{
            'request.side_effect': handle_request
        })


dummy_uaid = "00000000123412341234567812345678"
dummy_chid = "11111111123412341234567812345678"


class RegistrationTestCase(unittest.TestCase):

    def initialize(self):
        self.metrics = self.ap_settings.metrics

    def setUp(self):
        self.mock_dynamodb2 = mock_dynamodb2()
        self.mock_dynamodb2.start()
        twisted.internet.base.DelayedCall.debug = True
        settings = endpoint.RegistrationHandler.ap_settings =\
            AutopushSettings(
                hostname="localhost",
                statsd_host=None,
            )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.bridge_mock = settings.bridge = Mock(spec=Bridge)

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.reg = endpoint.RegistrationHandler(Application(),
                                                self.request_mock)

        self.status_mock = self.reg.set_status = Mock()
        self.write_mock = self.reg.write = Mock()

        d = self.finish_deferred = Deferred()
        self.reg.finish = lambda: d.callback(True)

    def tearDown(self):
        self.mock_dynamodb2.stop()

    def test_client_info(self):
        h = self.request_mock.headers
        h["user-agent"] = "myself"
        d = self.reg._client_info()
        eq_(d["user-agent"], "myself")
        self.request_mock.remote_ip = "local1"
        d = self.reg._client_info()
        eq_(d["remote-ip"], "local1")
        self.request_mock.headers["x-forwarded-for"] = "local2"
        d = self.reg._client_info()
        eq_(d["remote-ip"], "local2")

    def test_ap_settings_update(self):
        fake = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        reg = self.reg
        reg.ap_settings.update(banana="fruit")
        eq_(reg.ap_settings.banana, "fruit")
        reg.ap_settings.update(crypto_key=fake)
        eq_(reg.ap_settings.fernet._encryption_key,
            '\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00')

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_load_params_arguments(self, u=None):
        args = self.reg.request.arguments
        args['channelid'] = ['']
        args['connect'] = ['{"type":"test"}']
        self.assertTrue(self.reg._load_params())
        eq_(self.reg.chid, dummy_chid)
        eq_(self.reg.conn, '{"type":"test"}')

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_load_params_body(self, u=None):
        self.reg.request.body = b'connect={"type":"test"}'
        self.assertTrue(self.reg._load_params())
        eq_(self.reg.chid, dummy_chid)
        eq_(self.reg.conn, '{"type":"test"}')

    def test_load_params_invalid_body(self):
        self.reg.request.body = b'connect={"type":"test"}'
        self.assertTrue(not self.reg._load_params())

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_load_params_prefer_body(self, t):
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"invalid"}']
        self.reg.request.body = b'connect={"type":"test"}'
        self.assertTrue(self.reg._load_params())

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_load_params_no_conn(self, t):
        self.reg.request.body = b'noconnect={"type":"test"}'
        self.assertTrue(not self.reg._load_params())

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = False
        reg._addCors()
        assert reg._headers.get(ch1) != "*"
        assert reg._headers.get(ch2) != "GET,PUT"

        reg.clear_header(ch1)
        reg.clear_header(ch2)
        reg.ap_settings.cors = True
        reg._addCors()
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], "GET,PUT")

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.head(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], "GET,PUT")

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.options(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], "GET,PUT")

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_get_valid(self, arg):
        # All is well check.
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.ap_settings.endpoint_url = "http://localhost"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            called_arg = dict(useragentid=dummy_uaid,
                              channelid=dummy_chid,
                              endpoint="http://localhost/push/abcd123")
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            eq_(eval(args[0]), called_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get(dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_get_no_uuid(self, arg):
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.ap_settings.endpoint_url = "http://localhost"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(400, 'invalid UAID')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get(None)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_get_bad_uuid(self, arg):
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.ap_settings.endpoint_url = "http://localhost"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(400, 'invalid UAID')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get('invalid')
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_uaid)
    def test_put(self, arg):
        self.reg.bridge = self.bridge_mock
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"test"}']
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            called_arg = dict(useragentid=dummy_uaid,
                              channelid=dummy_uaid,
                              endpoint="http://localhost/push/abcd123")
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            eq_(eval(args[0]), called_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(None)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_uaid)
    def test_put_bad_uaid(self, arg):
        self.reg.bridge = self.bridge_mock
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"test"}']
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            called_arg = dict(useragentid=dummy_uaid,
                              channelid=dummy_uaid,
                              endpoint="http://localhost/push/abcd123")
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            eq_(eval(args[0]), called_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put('invalid')
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_uaid)
    def test_put_bad_params(self, arg):
        self.reg.bridge = self.bridge_mock
        args = self.reg.request.arguments
        args['invalid_connect'] = ['{"type":"test"}']
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(400, 'Invalid arguments')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put('')
        return self.finish_deferred

    def test_put_uaid_chid(self):
        self.reg.bridge = self.bridge_mock
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"test"}']
        args['channelid'] = [dummy_chid]
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            called_arg = dict(useragentid=dummy_uaid,
                              channelid=dummy_chid,
                              endpoint="http://localhost/push/abcd123")
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            eq_(eval(args[0]), called_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(dummy_uaid)
        return self.finish_deferred

    def test_bad_put(self):
        self.reg.bridge = self.bridge_mock
        self.bridge_mock.configure_mock(**{
            'register.return_value': False,
        })
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"test"}']
        args['channelid'] = [dummy_chid]
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(500, 'Registration failure')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(dummy_uaid)
        return self.finish_deferred

    def test_error_response(self):
        def handle_finish(value):
            self.reg.set_status.assert_called_with(
                500,
            )

        self.finish_deferred.addCallback(handle_finish)
        self.reg._error_response(Exception)
        return self.finish_deferred
