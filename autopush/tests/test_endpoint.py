import functools
import json

import requests
import twisted.internet.base
from boto.dynamodb2.exceptions import (
    ProvisionedThroughputExceededException,
)
from cryptography.fernet import Fernet, InvalidToken
from cyclone.web import Application
from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_
from twisted.internet.defer import Deferred
from twisted.trial import unittest
from txstatsd.metrics.metrics import Metrics

import autopush.endpoint as endpoint
from autopush.db import Router, Storage
from autopush.pinger.pinger import Pinger
from autopush.settings import AutopushSettings


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

        settings = endpoint.EndpointHandler.ap_settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.requests_mock = settings.requests = Mock(spec=requests.Session)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.pinger_mock = settings.pinger = Mock(spec=Pinger)

        self.request_mock = Mock(body=b'', arguments={})
        self.endpoint = endpoint.EndpointHandler(Application(),
                                                 self.request_mock)

        self.status_mock = self.endpoint.set_status = Mock()
        self.write_mock = self.endpoint.write = Mock()

        d = self.finish_deferred = Deferred()
        self.endpoint.finish = lambda: d.callback(True)

    def tearDown(self):
        self.mock_dynamodb2.stop()

    def test_load_params_arguments(self):
        args = self.endpoint.request.arguments
        args['version'] = ['123']
        args['data'] = ['ohai']
        self.endpoint._load_params()

        eq_(self.endpoint.version, 123)
        eq_(self.endpoint.data, 'ohai')

    def test_load_params_body(self):
        self.endpoint.request.body = b'version=1234&data=Hello%2c%20world!'
        self.endpoint._load_params()

        eq_(self.endpoint.version, 1234)
        eq_(self.endpoint.data, 'Hello, world!')

    @patch('time.time', return_value=1257894000)
    def test_load_params_invalid_body(self, t):
        self.endpoint.request.body = b'!@#$%^&[\x0d\x0a'
        self.endpoint._load_params()

        eq_(t.called, True)
        eq_(self.endpoint.version, 1257894000)
        eq_(self.endpoint.data, None)

    @patch('time.time', return_value=1257894000)
    def test_load_params_invalid_version(self, t):
        self.endpoint.request.body = b'version=bad&data=ohai'
        self.endpoint._load_params()

        eq_(t.called, True)
        eq_(self.endpoint.version, 1257894000)
        eq_(self.endpoint.data, 'ohai')

    @patch('time.time', return_value=1257894000)
    def test_load_params_negative_version(self, t):
        self.endpoint.request.body = b'version=-1&data=ohai'
        self.endpoint._load_params()

        eq_(t.called, True)
        eq_(self.endpoint.version, 1257894000)
        eq_(self.endpoint.data, 'ohai')

    @patch('time.time', return_value=1257894000)
    def test_load_params_prefer_body(self, t):
        args = self.endpoint.request.arguments
        args['version'] = ['123']
        args['data'] = ['ohai']
        self.endpoint.request.body = b'data=bai'
        self.endpoint._load_params()

        eq_(t.called, True)
        eq_(self.endpoint.version, 1257894000)
        eq_(self.endpoint.data, 'bai')

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

    def test_process_token_client_unknown(self):
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': None})

        def handle_finish(result):
            self.router_mock.get_uaid.assert_called_with('123')
            self.status_mock.assert_called_with(404)
            self.write_mock.assert_called_with('Invalid')
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.version, self.endpoint.data = 789, None

        self.endpoint._process_token('123:456')
        return self.finish_deferred

    def test_process_uaid_with_pping(self):
        self.pinger_mock.configure_mock(**{
            'ping.return_value': True})

        def handle_finish(result):
            self.assertTrue(result)
        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.pinger = self.pinger_mock
        self.endpoint.uaid = 'uaid'
        self.endpoint.version = 123
        self.endpoint.data = 'data'

        self.endpoint._process_uaid({"proprietary_ping": '{"type":"test"}'})
        return self.finish_deferred

    def test_process_pping_with_bad_ping(self):
        self.requests_mock.configure_mock(**{
            'put.return_value.status_code': 200,
        })

        def handle_finish(result):
            # message is presumed routed through the relay
            self.assertTrue(result)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.pinger = self.pinger_mock
        # skipping a fair number of pre-emptory steps.
        self.endpoint.chid = 'chid'
        self.endpoint.uaid = 'uaid'
        self.endpoint.version = 123
        self.endpoint.data = 'data'
        self.endpoint.start_time = 0

        self.endpoint._process_pping(False, {'node_id': 'node_id'})
        return self.finish_deferred

    def test_process_token_client_jumped(self):
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': {'node_id': ''}})
        self.storage_mock.configure_mock(**{
            'save_notification.return_value': True})

        def handle_finish(result):
            self.storage_mock.save_notification.assert_called_with(
                uaid='123', chid='456', version=789)
            self.router_mock.get_uaid.assert_called_with('123')
            self._assert_miss_response()
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.version = 789

        self.endpoint._process_token('123:456')
        return self.finish_deferred

    def test_process_token_client_busy(self):
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': {'node_id': 'https://example.com'}})
        self.requests_mock.configure_mock(**{
            'put.side_effect': lambda url, **kwargs: Mock(
                status_code=503 if '/push/' in url else 200)})
        self.storage_mock.configure_mock(**{
            'save_notification.return_value': True})

        def handle_save(result):
            eq_(self.endpoint.client_check, True)
            self._assert_push_request('https://example.com/push/123')
            calls = self.requests_mock.put.mock_calls
            eq_(len(calls), 2)
            _, (url,), params = calls[1]
            eq_(url, 'https://example.com/notif/123')
            self._assert_miss_response()
        self.finish_deferred.addCallback(handle_save)

        self.endpoint.version, self.endpoint.data = 789, None

        self.endpoint._process_token('123:456')
        return self.finish_deferred

    def test_process_token_conditional_delete_success(self):
        node_record = {'node_id': 'https://example.com'}
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': node_record,
            'clear_node.return_value': True})
        self.storage_mock.configure_mock(**{
            'save_notification.return_value': True})
        self.requests_mock.configure_mock(**{
            'put.return_value.status_code': 404})
        d = Deferred()
        jumped_client_mock = Mock(side_effect=lambda *args, **kwargs:
                                  d.callback(True))
        self.endpoint._process_jumped_client = jumped_client_mock

        def handle_finish(result):
            self.requests_mock.put.assert_called_with(
                'https://example.com/push/123',
                data=json.dumps([{
                    "channelID": '456',
                    'version': 789,
                    'data': 'ohai'
                }]),
            )
            self.router_mock.clear_node.assert_called_with(node_record)
            self.storage_mock.save_notification.assert_called_with(
                uaid='123', chid='456', version=789)
        d.addCallback(handle_finish)

        self.endpoint.version, self.endpoint.data = 789, 'ohai'

        self.endpoint._process_token('123:456')
        return d

    def test_process_token_conditional_delete_fail(self):
        node_record = {'node_id': 'https://example.com'}
        self.requests_mock.configure_mock(**{
            'put.return_value.status_code': 404})
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': node_record,
            'clear_node.return_value': False})

        def handle_delete(result):
            self.requests_mock.put.assert_called_with(
                'https://example.com/push/123',
                data=json.dumps([{
                    "channelID": '456',
                    'version': 789,
                    'data': 'ohai'
                }]),
            )
            self.router_mock.clear_node.assert_called_with(node_record)
            self.status_mock.assert_called_with(503)
            self.write_mock.assert_called_with('Server is busy')
        self.finish_deferred.addCallback(handle_delete)

        self.endpoint.version, self.endpoint.data = 789, 'ohai'

        self.endpoint._process_token('123:456')
        return self.finish_deferred

    def test_process_token_throughput_exceeded(self):
        self.router_mock.configure_mock(**{
            'get_uaid.side_effect': ProvisionedThroughputExceededException(
                402, 'pay up or el$e')})

        def handle_finish(result):
            self.router_mock.get_uaid.assert_called_with('123')
            self._assert_throughput_exceeded_response()
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.version, self.endpoint.data = 789, None

        self.endpoint._process_token('123:456')
        return self.finish_deferred

    def test_save_notification_client_jumped(self):
        self.storage_mock.configure_mock(**{
            'save_notification.return_value': True})
        self.requests_mock.configure_mock(**{
            'put.side_effect': lambda url, **kwargs: Mock(
                status_code=404 if 'example.com' in url else 200)
        })
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': {
                'node_id': 'https://example.org'}})

        def handle_finish(result):
            self.storage_mock.save_notification.assert_called_with(
                uaid='123', chid='456', version=789)
            calls = self.requests_mock.put.mock_calls
            eq_(len(calls), 2)
            _, (old_node_url,), _ = calls[0]
            eq_(old_node_url, 'https://example.com/notif/123')
            self.router_mock.get_uaid.assert_called_with('123')
            _, (new_node_url,), _ = calls[1]
            eq_(new_node_url, 'https://example.org/notif/123')
            self._assert_miss_response()
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.uaid, self.endpoint.chid = '123', '456'
        self.endpoint.version = 789
        self.endpoint.client_check = True

        self.endpoint._save_notification('https://example.com')
        return self.finish_deferred

    def test_save_notification_client_deleted(self):
        self.storage_mock.configure_mock(**{
            'save_notification.return_value': True})
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': None})

        def handle_finish(result):
            self.storage_mock.save_notification.assert_called_with(
                uaid='123', chid='456', version=789)
            self.router_mock.get_uaid.assert_called_with('123')
            self.status_mock.assert_called_with(404)
            self.write_mock.assert_called_with('Invalid')
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.uaid, self.endpoint.chid = '123', '456'
        self.endpoint.version = 789
        self.endpoint.client_check = False

        self.endpoint._save_notification('https://example.com')
        return self.finish_deferred

    @patch_logger
    def test_save_notification_storage_error(self, log_mock):
        self.storage_mock.configure_mock(**{
            'save_notification.side_effect': IOError})

        def handle_finish(result):
            self.storage_mock.save_notification.assert_called_with(
                uaid='123', chid='456', version=789)
            self.status_mock.assert_called_with(500)
            self.write_mock.assert_called_with('Error processing request')
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.uaid, self.endpoint.chid = '123', '456'
        self.endpoint.version = 789

        self.endpoint._save_notification('https://example.com')
        return self.finish_deferred

    def test_process_routing_throughput_exceeded(self):
        self.requests_mock.configure_mock(**{
            'put.return_value.status_code': 404
        })
        self.router_mock.configure_mock(**{
            'clear_node.side_effect': ProvisionedThroughputExceededException(
                402, 'pay up or el$e')
        })

        def handle_finish(result):
            eq_(self.endpoint.client_check, False)
            self._assert_push_request('https://example.com/push/123')
            self._assert_throughput_exceeded_response()
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.uaid, self.endpoint.chid = '123', '456'
        self.endpoint.version, self.endpoint.data = 789, None

        # skip pping handler in _process_uaid.
        self.endpoint._process_route({'node_id': 'https://example.com'})
        return self.finish_deferred

    def test_process_save_throughput_exceeded(self):
        self.router_mock.configure_mock(**{
            'get_uaid.side_effect': ProvisionedThroughputExceededException(
                402, 'pay up or el$e')
        })

        def handle_finish(result):
            self.router_mock.get_uaid.assert_called_with('123')
            self._assert_throughput_exceeded_response()
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.uaid, self.endpoint.chid = '123', '456'
        self.endpoint.version = 789
        self.endpoint.client_check = False

        self.endpoint._process_save(None)
        return self.finish_deferred

    def test_put_routing_hit(self):
        self.fernet_mock.configure_mock(**{
            'decrypt.return_value': b'123:456'})
        self.router_mock.configure_mock(**{
            'get_uaid.return_value': {
                'node_id': 'https://example.org'
            },
        })
        self.requests_mock.configure_mock(**{
            'put.return_value.status_code': 200})

        def handle_finish(result):
            self.fernet_mock.decrypt.assert_called_with('token')
            self.router_mock.get_uaid.assert_called_with('123')
            self.requests_mock.put.assert_called_with(
                'https://example.org/push/123',
                data=json.dumps([{
                    'channelID': '456',
                    'version': 789,
                    'data': 'ohai'
                }]),
            )
            self.metrics_mock.increment.assert_called_with(
                'router.broadcast.hit')
            eq_(len(self.metrics_mock.timing.mock_calls), 1)
            _, (name,), _ = self.metrics_mock.timing.mock_calls[0]
            eq_(name, 'updates.handled')
            self.write_mock.assert_called_with('Success')
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.request.body = b'version=789&data=ohai'
        self.endpoint.put('token')
        return self.finish_deferred

    def test_process_jumped_client_hit(self):
        self.requests_mock.configure_mock(**{
            'put.return_value.status_code': 200})
        return self._assert_jumped_client()

    def test_process_jumped_client_miss(self):
        self.requests_mock.configure_mock(**{
            'put.return_value.status_code': 404})
        return self._assert_jumped_client()

    def test_process_jumped_client_error(self):
        self.requests_mock.configure_mock(**{
            'put.side_effect': IOError})
        return self._assert_jumped_client()

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
        endpoint.head(None)
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], "PUT")

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = True
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

        self.endpoint.write_error(999, testX)
        self.status_mock.assert_called_with(999)
        self.assertTrue(log_mock.err.called)

    def _assert_jumped_client(self):
        def handle_finish(result):
            self.requests_mock.put.assert_called_with(
                'https://example.com/notif/123')
            self._assert_miss_response()
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.uaid = '123'

        self.endpoint._process_jumped_client({
            'node_id': 'https://example.com'})
        return self.finish_deferred

    def _assert_push_request(self, expected_url):
        calls = self.requests_mock.put.mock_calls
        eq_(len(calls) >= 1, True)
        _, (actual_url,), params = calls[0]
        eq_(actual_url, expected_url)
        eq_('data' in params, True)

    def _assert_error_response(self, result):
        self.status_mock.assert_called_with(500)
        self.write_mock.assert_called_with("Error processing request")

    def _assert_throughput_exceeded_response(self):
        self.status_mock.assert_called_with(503)
        self.write_mock.assert_called_with('Server busy, try later')

    def _assert_miss_response(self):
        self.metrics_mock.increment.assert_called_with('router.broadcast.miss')
        self.write_mock.assert_called_with('Success')


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
        self.requests_mock = settings.requests = Mock(spec=requests.Session)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.pinger_mock = settings.pinger = Mock(spec=Pinger)

        self.request_mock = Mock(body=b'', arguments={})
        self.reg = endpoint.RegistrationHandler(Application(),
                                                self.request_mock)

        self.status_mock = self.reg.set_status = Mock()
        self.write_mock = self.reg.write = Mock()

        d = self.finish_deferred = Deferred()
        self.reg.finish = lambda: d.callback(True)

    def tearDown(self):
        self.mock_dynamodb2.stop()

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
        self.reg.ap_settings.endpont_url = "http://localhost"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            self.reg.write.assert_called_with(
                '{"useragentid": "' + dummy_uaid + '", '
                '"channelid": "' + dummy_chid + '", '
                '"endpoint": "http://localhost/push/abcd123"}')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get(dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_chid)
    def test_get_no_uuid(self, arg):
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.ap_settings.endpont_url = "http://localhost"

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
        self.reg.ap_settings.endpont_url = "http://localhost"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(400, 'invalid UAID')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get('invalid')
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_uaid)
    def test_put(self, arg):
        self.reg.pinger = self.pinger_mock
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"test"}']
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            self.reg.write.assert_called_with(
                '{"useragentid": "' + dummy_uaid + '", '
                '"channelid": "' + dummy_uaid + '", '
                '"endpoint": "http://localhost/push/abcd123"}')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(None)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_uaid)
    def test_put_bad_uaid(self, arg):
        self.reg.pinger = self.pinger_mock
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"test"}']
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            self.reg.write.assert_called_with(
                '{"useragentid": "' + dummy_uaid + '", '
                '"channelid": "' + dummy_uaid + '", '
                '"endpoint": "http://localhost/push/abcd123"}')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put('invalid')
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=dummy_uaid)
    def test_put_bad_params(self, arg):
        self.reg.pinger = self.pinger_mock
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
        self.reg.pinger = self.pinger_mock
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"test"}']
        args['channelid'] = [dummy_chid]
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(200)
            self.reg.write.assert_called_with(
                '{"useragentid": "' + dummy_uaid + '", '
                '"channelid": "' + dummy_chid + '", '
                '"endpoint": "http://localhost/push/abcd123"}')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(dummy_uaid)
        return self.finish_deferred

    def test_bad_put(self):
        self.reg.pinger = self.pinger_mock
        self.pinger_mock.configure_mock(**{
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
