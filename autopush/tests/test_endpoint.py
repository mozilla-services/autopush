import functools
import json
import sys
import time
import uuid

import twisted.internet.base
from cryptography.fernet import Fernet, InvalidToken
from cyclone.web import Application
from mock import Mock, patch
from moto import mock_dynamodb2, mock_s3
from nose.tools import eq_, ok_
from twisted.internet.defer import Deferred
from twisted.trial import unittest
from twisted.web.client import Agent, Response
from txstatsd.metrics.metrics import Metrics

import autopush.endpoint as endpoint
from autopush.db import (
    ProvisionedThroughputExceededException,
    Router,
    Storage,
    Message,
    ItemNotFound
)
from autopush.settings import AutopushSettings
from autopush.router.interface import IRouter, RouterResponse
from autopush.senderids import SenderIDs
from autopush.utils import generate_hash

mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()
    mock_s3().start()


def tearDown():
    mock_dynamodb2.stop()
    mock_s3().stop()


class FileConsumer(object):  # pragma: no cover
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


class MessageTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        settings = self.ap_settings = endpoint.MessageHandler.ap_settings =\
            AutopushSettings(
                hostname="localhost",
                statsd_host=None,
                crypto_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.message_mock = settings.message = Mock(spec=Message)

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.message = endpoint.MessageHandler(Application(),
                                               self.request_mock,
                                               ap_settings=settings)

        self.status_mock = self.message.set_status = Mock()
        self.write_mock = self.message.write = Mock()

        d = self.finish_deferred = Deferred()
        self.message.finish = lambda: d.callback(True)

    def test_delete_token_invalid(self):
        self.fernet_mock.configure_mock(**{
            "decrypt.side_effect": InvalidToken})

        def handle_finish(result):
            self.status_mock.assert_called_with(404)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete('')
        return self.finish_deferred

    def test_delete_token_wrong_components(self):
        self.fernet_mock.decrypt.return_value = "123:456"

        def handle_finish(result):
            self.status_mock.assert_called_with(404)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete('')
        return self.finish_deferred

    def test_delete_token_wrong_kind(self):
        self.fernet_mock.decrypt.return_value = "r:123:456"

        def handle_finish(result):
            self.status_mock.assert_called_with(404)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete('')
        return self.finish_deferred

    def test_delete_success(self):
        self.fernet_mock.decrypt.return_value = "m:123:456"
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})

        def handle_finish(result):
            self.message_mock.delete_message.assert_called_with(
                "123", "456", "123-456")
            self.status_mock.assert_called_with(204)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete("123-456")
        return self.finish_deferred

    def test_delete_db_error(self):
        self.fernet_mock.decrypt.return_value = "m:123:456"
        self.message_mock.configure_mock(**{
            "delete_message.side_effect":
            ProvisionedThroughputExceededException(None, None)})

        def handle_finish(result):
            self.assertTrue(result)
            self.status_mock.assert_called_with(503)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete('')
        return self.finish_deferred

    def test_update_bad_ttl_value_and_missing_crypto_headers(self):
        uaid = uuid.uuid4().hex
        chid = uuid.uuid4().hex
        self.fernet_mock.decrypt.return_value = "m:%s:%s" % (uaid, chid)
        self.request_mock.headers = {"ttl": "fred"}
        self.request_mock.body = "some data"
        self.message.version = "asdf"

        def handle_finish(result):
            self.assertTrue(result)
            self.status_mock.assert_called_with(400)

        self.finish_deferred.addCallback(handle_finish)
        self.message.put("")
        return self.finish_deferred

    def test_update_too_much_data(self):
        self.fernet_mock.decrypt.return_value = "m:123:456"
        self.ap_settings.max_data = 2
        self.request_mock.headers = {"ttl": "fred"}
        self.request_mock.body = "some data"
        self.message.version = "asdf"

        def handle_finish(result):
            self.assertTrue(result)
            self.status_mock.assert_called_with(413)
            data = self.write_mock.call_args[0][0]
            d = json.loads(data)
            self.assertEqual(d.get("message"), "Data payload too large")

        self.finish_deferred.addCallback(handle_finish)
        self.message.put("")
        return self.finish_deferred


class EndpointTestCase(unittest.TestCase):
    def setUp(self):
        self.timeout = 0.5

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
        self.senderIDs_mock = settings.senderIDs = Mock(spec=SenderIDs)
        self.senderIDs_mock.get_ID.return_value = "test_senderid"

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.endpoint = endpoint.EndpointHandler(Application(),
                                                 self.request_mock,
                                                 ap_settings=settings)
        self.settings = settings
        settings.routers["simplepush"] = Mock(spec=IRouter)
        settings.routers["webpush"] = Mock(spec=IRouter)
        self.sp_router_mock = settings.routers["simplepush"]
        self.wp_router_mock = settings.routers["webpush"]
        self.status_mock = self.endpoint.set_status = Mock()
        self.write_mock = self.endpoint.write = Mock()

        d = self.finish_deferred = Deferred()
        self.endpoint.finish = lambda: d.callback(True)
        self.endpoint.start_time = time.time()

    def _check_error(self, code, errno, error):
        d = json.loads(self.write_mock.call_args[0][0])
        eq_(d.get("code"), code)
        eq_(d.get("errno"), errno)
        eq_(d.get("error"), error)

    def test_uaid_lookup_results(self):
        fresult = dict(router_type="test")
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.endpoint.ap_settings.routers["test"] = frouter
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            assert(frouter.route_notification.called)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_uaid_lookup_results_bad_ttl(self):
        fresult = dict(router_type="test")
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.request_mock.headers["ttl"] = "woops"
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.endpoint.ap_settings.routers["test"] = frouter
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            assert(frouter.route_notification.called)
            args, kwargs = frouter.route_notification.call_args
            notif = args[0]
            assert(notif.ttl == 0)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_webpush_ttl_too_large(self):
        from autopush.endpoint import MAX_TTL
        fresult = dict(router_type="test")
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.request_mock.headers["ttl"] = MAX_TTL + 100
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.endpoint.ap_settings.routers["test"] = frouter
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            assert(frouter.route_notification.called)
            args, kwargs = frouter.route_notification.call_args
            notif = args[0]
            eq_(notif.ttl, MAX_TTL)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_webpush_bad_routertype(self):
        fresult = dict(router_type="fred")
        self.endpoint.chid = "fred"
        self.request_mock.body = b"stuff"
        self.endpoint._uaid_lookup_results(fresult)

        self.endpoint.set_status.assert_called_with(400)
        data = self.write_mock.call_args[0][0]
        d = json.loads(data)
        eq_(d.get("errno"), 108)

    # Crypto headers should be required for Web Push...
    def test_webpush_uaid_lookup_no_crypto_headers_with_data(self):
        fresult = dict(router_type="webpush")
        frouter = self.settings.routers["webpush"]
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.request_mock.body = b"stuff"
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            self.endpoint.set_status.assert_called_with(400)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    # ...But can be omitted for blank messages...
    def test_webpush_uaid_lookup_no_crypto_headers_without_data(self):
        fresult = dict(router_type="webpush")
        frouter = self.settings.routers["webpush"]
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            assert(frouter.route_notification.called)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    # ...And for other router types.
    def test_other_uaid_lookup_no_crypto_headers(self):
        fresult = dict(router_type="test")
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.endpoint.ap_settings.routers["test"] = frouter
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            assert(frouter.route_notification.called)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_webpush_payload_encoding(self):
        fresult = dict(router_type="webpush")
        frouter = self.settings.routers["webpush"]
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.request_mock.body = b"\xc3\x28\xa0\xa1"
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            calls = frouter.route_notification.mock_calls
            eq_(len(calls), 1)
            (_, (notification, _), _) = calls[0]
            eq_(notification.channel_id, "fred")
            eq_(notification.data, b"wyigoQ==")

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_other_payload_encoding(self):
        fresult = dict(router_type="test")
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = "fred"
        self.endpoint.ap_settings.routers["test"] = frouter

        self.request_mock.body = b"stuff"
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            calls = frouter.route_notification.mock_calls
            eq_(len(calls), 1)
            (_, (notification, _), _) = calls[0]
            eq_(notification.channel_id, "fred")
            eq_(notification.data, b"stuff")

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

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
        self.fernet_mock.decrypt.return_value = "123:456"
        self.endpoint.ap_settings.router.get_uaid.return_value = {}
        self.endpoint.ap_settings.max_data = 3
        self.endpoint.request.body = b'version=1&data=1234'

        def handle_finish(result):
            self.endpoint.set_status.assert_called_with(413)
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
            self.status_mock.assert_called_with(404)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put('')
        return self.finish_deferred

    def test_put_token_wrong(self):
        self.fernet_mock.decrypt.return_value = "123:456:789"
        self.endpoint.request.body = b'version=123'

        def handle_finish(result):
            self.status_mock.assert_called_with(404)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put('')
        return self.finish_deferred

    def _throw_item_not_found(self, item):
        raise ItemNotFound("User not found")

    def _throw_provisioned_error(self, *args):
        raise ProvisionedThroughputExceededException(None, None)

    def test_process_token_client_unknown(self):
        self.router_mock.configure_mock(**{
            'get_uaid.side_effect': self._throw_item_not_found})

        def handle_finish(result):
            self.router_mock.get_uaid.assert_called_with('123')
            self.status_mock.assert_called_with(404)
            self._check_error(404, 103, "Not Found")
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.version, self.endpoint.data = 789, None

        self.endpoint._token_valid('123:456')
        return self.finish_deferred

    def test_put_default_router(self):
        self.fernet_mock.decrypt.return_value = "123:456"
        self.router_mock.get_uaid.return_value = dict()
        self.sp_router_mock.route_notification.return_value = RouterResponse()

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(200)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(dummy_uaid)
        return self.finish_deferred

    def test_put_router_needs_change(self):
        self.fernet_mock.decrypt.return_value = "123:456"
        self.router_mock.get_uaid.return_value = dict(
            router_type="simplepush",
            router_data=dict(),
        )
        self.sp_router_mock.route_notification.return_value = RouterResponse(
            status_code=500,
            router_data={},
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(500)
            assert(self.router_mock.register_user.called)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(dummy_uaid)
        return self.finish_deferred

    def test_put_router_needs_update(self):
        self.fernet_mock.decrypt.return_value = "123:456"
        self.router_mock.get_uaid.return_value = dict(
            router_type="simplepush",
            router_data=dict(),
        )
        self.sp_router_mock.route_notification.return_value = RouterResponse(
            status_code=503,
            router_data=dict(token="new_connect"),
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(503)
            assert(self.router_mock.register_user.called)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_with_headers_in_response(self):
        self.fernet_mock.decrypt.return_value = "123:456"
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
            headers={"Location": "Somewhere"}
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(201)
            self.endpoint.set_header.assert_called_with(
                "Location", "Somewhere")
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.post(dummy_uaid)
        return self.finish_deferred

    def test_put_db_error(self):
        self.fernet_mock.decrypt.return_value = "123:456"
        self.router_mock.get_uaid.side_effect = self._throw_provisioned_error

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(503)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(dummy_uaid)
        return self.finish_deferred

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = False
        assert endpoint._headers.get(ch1) != "*"
        assert endpoint._headers.get(ch2) != "POST,PUT"
        assert endpoint._headers.get(ch3) != ("content-encoding,encryption,"
                                              "encryption-key,content-type")
        assert endpoint._headers.get(ch4) != "location"

        endpoint.clear_header(ch1)
        endpoint.clear_header(ch2)
        endpoint.ap_settings.cors = True
        self.endpoint.prepare()
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], "POST,PUT")
        eq_(endpoint._headers[ch3], "content-encoding,encryption,"
            "encryption-key,content-type")
        eq_(endpoint._headers[ch4], "location")

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = True
        endpoint.prepare()
        endpoint.head(None)
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], "POST,PUT")
        eq_(endpoint._headers[ch3], "content-encoding,encryption,"
            "encryption-key,content-type")
        eq_(endpoint._headers[ch4], "location")

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = True
        endpoint.prepare()
        endpoint.options(None)
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], "POST,PUT")
        eq_(endpoint._headers[ch3], "content-encoding,encryption,"
            "encryption-key,content-type")
        eq_(endpoint._headers[ch4], "location")

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

    def _assert_error_response(self, result):
        self.status_mock.assert_called_with(500)


dummy_uaid = "00000000123412341234567812345678"
dummy_chid = "11111111123412341234567812345678"
CORS_HEAD = "GET,PUT,DELETE"


class RegistrationTestCase(unittest.TestCase):

    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        settings = endpoint.RegistrationHandler.ap_settings =\
            AutopushSettings(
                hostname="localhost",
                statsd_host=None,
                auth_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=',
            )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.senderIDs_mock = settings.senderIDs = Mock(spec=SenderIDs)
        self.senderIDs_mock.get_ID.return_value = "test_senderid"

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.reg = endpoint.RegistrationHandler(Application(),
                                                self.request_mock,
                                                ap_settings=settings)

        self.status_mock = self.reg.set_status = Mock()
        self.write_mock = self.reg.write = Mock()
        self.auth = ("Bearer %s" %
                     generate_hash(self.reg.ap_settings.auth_key[0],
                                   dummy_uaid))

        d = self.finish_deferred = Deferred()
        self.reg.finish = lambda: d.callback(True)

    def _check_error(self, code, errno, error):
        d = json.loads(self.write_mock.call_args[0][0])
        eq_(d.get("code"), code)
        eq_(d.get("errno"), errno)
        eq_(d.get("error"), error)

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
        eq_(reg.ap_settings.fernet._fernets[0]._encryption_key,
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_load_params_arguments(self, u=None):
        self.reg.request.body = json.dumps(dict(
            channelID=dummy_chid,
            type="test",
        ))
        result = self.reg._load_params()
        self.assert_(isinstance(result, dict))
        eq_(result["channelID"], dummy_chid)

    def test_load_params_invalid_body(self):
        self.reg.request.body = b'connect={"type":"test"}'
        self.assertTrue(not self.reg._load_params())

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_load_params_prefer_body(self, t):
        args = self.reg.request.arguments
        args['connect'] = ['{"type":"invalid"}']
        self.reg.request.body = b'connect={"type":"test"}'
        self.assertTrue(self.reg._load_params())

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_load_params_no_conn(self, t):
        self.reg.request.body = b'noconnect={"type":"test"}'
        self.assertTrue(not self.reg._load_params())

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = False
        assert reg._headers.get(ch1) != "*"
        assert reg._headers.get(ch2) != CORS_HEAD

        reg.clear_header(ch1)
        reg.clear_header(ch2)
        reg.ap_settings.cors = True
        reg.prepare()
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], CORS_HEAD)

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.prepare()
        reg.head(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], CORS_HEAD)

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.prepare()
        reg.options(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], CORS_HEAD)

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_get_valid(self, *args):
        # All is well check.
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        user_item = dict(
            router_type="simplepush",
            router_data={},
        )
        self.reg.ap_settings.endpoint_url = "http://localhost"
        self.reg.request.headers["Authorization"] = self.auth
        self.router_mock.get_uaid.return_value = user_item

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            retval = dict(
                type=user_item["router_type"],
                data=user_item["router_data"])
            eq_(json.loads(args[0]), retval)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get(dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_get_no_uuid(self, *args):
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.ap_settings.endpoint_url = "http://localhost"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(401)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get()
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_get_bad_uuid(self, *args):
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.ap_settings.endpoint_url = "http://localhost"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(401)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get('invalid')
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post(self, *args):
        self.reg.ap_settings.routers["test"] = self.router_mock
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=dummy_chid,
            data={},
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["uaid"], dummy_uaid)
            eq_(call_arg["endpoint"], "http://localhost/push/abcd123")
            ok_("secret" in call_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.post()
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_invalid_args(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="test",
            data={},
        ))

        def handle_finish(value):
            self._check_error(400, 108, "Bad Request")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post()
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_bad_router_type(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="test",
            channelID=dummy_chid,
            data={},
        ))

        def handle_finish(value):
            self._check_error(400, 108, "Bad Request")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post()
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_post_existing_uaid(self, *args):
        self.reg.request.headers["Authorization"] = "Fred Smith"
        self.reg.request.body = json.dumps(dict(
            channelID=dummy_chid,
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/push/abcd123")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_bad_uaid(self, *args):
        self.reg.ap_settings.routers["test"] = self.router_mock
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=dummy_chid,
            data={},
        ))

        def handle_finish(value):
            self._check_error(401, 109, "Unauthorized")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post('invalid')
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_bad_params(self, *args):
        self.reg.ap_settings.routers["test"] = self.router_mock
        self.reg.request.body = json.dumps(dict(
            channelID=dummy_chid,
        ))

        def handle_finish(value):
            self._check_error(401, 109, 'Unauthorized')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = "Bearer Invalid"
        self.reg.post(dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_uaid_chid(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=dummy_chid,
            data={},
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["uaid"], dummy_uaid)
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/push/abcd123")
            ok_("secret" in call_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post()
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_post_nochid(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            data={},
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["uaid"], dummy_chid)
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/push/abcd123")
            ok_("secret" in call_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post()
        return self.finish_deferred

    @patch('autopush.endpoint.log')
    def test_post_bad(self, *args):
        from autopush.router.interface import RouterException
        self.reg.ap_settings.routers["test"] = router_mock = Mock(spec=IRouter)

        def bad_register(uaid, connect):
            raise RouterException("stuff", status_code=500,
                                  response_body="Registration badness")
        router_mock.register.side_effect = bad_register
        self.reg.request.body = json.dumps(dict(
            type="test",
            channelID=dummy_chid,
            data={},
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self.reg.set_status.assert_called_with(500)
            self.flushLoggedErrors()

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = "Bearer Invalid"
        self.reg.post()
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_put(self, *args):
        self.reg.ap_settings.routers["apns"] = mock_apns = Mock(spec=IRouter)
        data = dict(token="some_token")
        mock_apns.register.return_value = data
        self.reg.request.body = json.dumps(dict(
            type="apns",
            data=data,
        ))

        def handle_finish(value):
            self.reg.write.assert_called_with({})
            mock_apns.register.assert_called_with(dummy_uaid, data)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.put(dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_put_bad_auth(self, *args):
        self.reg.request.headers["Authorization"] = "Fred Smith"

        def handle_finish(value):
            self._check_error(401, 109, "Unauthorized")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_put_bad_arguments(self, *args):
        self.reg.request.headers["Authorization"] = self.auth
        data = dict(token="some_token")
        self.reg.request.body = json.dumps(dict(
            type="apns",
            data=data,
        ))

        def handle_finish(value):
            self._check_error(400, 108, "Bad Request")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(dummy_uaid)
        return self.finish_deferred

    def test_delete_chid(self, *args):
        self.reg.request.headers["Authorization"] = self.auth
        path = "%s/%s" % (dummy_uaid, dummy_chid)
        d = self.reg.delete(path)
        return d

    def test_delete_uaid(self, *args):
        self.reg.ap_settings.message.store_message(
            dummy_uaid,
            dummy_chid,
            "1",
            10000)
        self.reg.ap_settings.message.store_message(
            dummy_uaid,
            "test",
            "2",
            10000)
        self.reg.request.headers["Authorization"] = self.auth
        path = "%s" % dummy_uaid
        d = self.reg.delete(path)
        return d

    def test_delete_bad_uaid(self, *args):
        self.reg.request.headers["Authorization"] = self.auth
        d = self.reg.delete("/%s/" % dummy_uaid)
        return d

    def test_delete_bad_auth(self, *args):
        self.reg.request.headers["Authorization"] = "Invalid"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(401)

        self.finish_deferred.addCallback(handle_finish)
        d = self.reg.delete("/%s/" % dummy_uaid)
        return d

    def test_validate_auth(self):
        eq_(False, self.reg._validate_auth(dummy_uaid))
        self.reg.request.headers['Authorization'] = self.auth
        eq_(True, self.reg._validate_auth(dummy_uaid))
        self.reg.ap_settings.auth_key = []
        eq_(True, self.reg._validate_auth(dummy_uaid))
