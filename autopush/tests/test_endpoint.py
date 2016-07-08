import json
import sys
import time
import uuid
import random
import base64

from hashlib import sha256

import ecdsa
import twisted.internet.base
from cryptography.fernet import Fernet, InvalidToken
from cyclone.web import Application
from jose import jws
from mock import Mock, patch
from moto import mock_dynamodb2, mock_s3
from nose.tools import eq_, ok_, assert_raises
from twisted.internet.defer import Deferred
from twisted.trial import unittest
from twisted.web.client import Agent, Response
from txstatsd.metrics.metrics import Metrics


import autopush.endpoint as endpoint
import autopush.utils as utils
from autopush.db import (
    ProvisionedThroughputExceededException,
    Router,
    Storage,
    Message,
    ItemNotFound,
    create_rotating_message_table,
    has_connected_this_month,
    hasher
)
from autopush.exceptions import InvalidTokenException
from autopush.settings import AutopushSettings
from autopush.router.interface import IRouter, RouterResponse
from autopush.utils import (generate_hash, decipher_public_key)

mock_dynamodb2 = mock_dynamodb2()
dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))
dummy_token = dummy_uaid + ":" + dummy_chid


def setUp():
    mock_dynamodb2.start()
    mock_s3().start()
    create_rotating_message_table()


def tearDown():
    mock_dynamodb2.stop()
    mock_s3().stop()


class FileConsumer(object):  # pragma: no cover
    def __init__(self, file):
        self.file = file

    def write(self, data):
        self.file.write(data)


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
            self.status_mock.assert_called_with(400, None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete('')
        return self.finish_deferred

    def test_delete_token_wrong_components(self):
        self.fernet_mock.decrypt.return_value = "123:456"

        def handle_finish(result):
            self.status_mock.assert_called_with(400, None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete('')
        return self.finish_deferred

    def test_delete_token_wrong_kind(self):
        self.fernet_mock.decrypt.return_value = "r:123:456"

        def handle_finish(result):
            self.status_mock.assert_called_with(400, None)
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
            self.status_mock.assert_called_with(503, None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete('')
        return self.finish_deferred

dummy_request_id = "11111111-1234-1234-1234-567812345678"


class EndpointTestCase(unittest.TestCase):
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

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_request_id))
    def setUp(self, t):
        from twisted.logger import Logger
        # this timeout *should* be set to 0.5, however Travis runs
        # so slow, that many of these tests will time out leading
        # to false failure rates and integration tests generally
        # failing.
        self.timeout = 1

        twisted.internet.base.DelayedCall.debug = True

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.old_fernet = settings.fernet
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.agent_mock = settings.agent = Mock(spec=Agent)
        self.response_mock = Mock(spec=Response)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)

        self.request_mock = Mock(body=b'', arguments={},
                                 headers={"ttl": "0"},
                                 host='example.com:8080')
        self.endpoint = endpoint.EndpointHandler(Application(),
                                                 self.request_mock,
                                                 ap_settings=settings)
        self.settings = settings
        settings.routers["simplepush"] = Mock(spec=IRouter)
        settings.routers["webpush"] = Mock(spec=IRouter)
        settings.routers["test"] = Mock(spec=IRouter)
        self.sp_router_mock = settings.routers["simplepush"]
        self.wp_router_mock = settings.routers["webpush"]
        self.status_mock = self.endpoint.set_status = Mock()
        self.write_mock = self.endpoint.write = Mock()
        self.endpoint.log = Mock(spec=Logger)

        d = self.finish_deferred = Deferred()
        self.endpoint.finish = lambda: d.callback(True)
        self.endpoint.start_time = time.time()

    def _check_error(self, code, errno, error=None, message=None):
        d = json.loads(self.write_mock.call_args[0][0])
        eq_(d.get("code"), code)
        eq_(d.get("errno"), errno)
        if error is not None:
            eq_(d.get("error"), error)
        if message:
            eq_(d.get("message"), message)

    def test_uaid_lookup_results(self):
        fresult = dict(router_type="test")
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = dummy_chid
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
        self.endpoint.chid = dummy_chid
        self.request_mock.headers["ttl"] = "woops"
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.endpoint.ap_settings.routers["test"] = frouter
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            self.endpoint.set_status.assert_called_with(400, None)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_webpush_ttl_too_large(self):
        from autopush.endpoint import MAX_TTL
        fresult = dict(router_type="test")
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = dummy_chid
        self.request_mock.headers["ttl"] = str(MAX_TTL + 100)
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

    def test_webpush_missing_ttl(self):
        del(self.request_mock.headers['ttl'])
        frouter = Mock(spec=Router)
        frouter.route_notification = Mock()
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.ap_settings.routers["webpush"] = frouter
        self.endpoint._uaid_lookup_results(dict(router_type="webpush"))

        def handle_finish(value):
            self.endpoint.set_status.assert_called_with(200)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_webpush_missing_ttl_user_offline(self):
        from autopush.router.interface import RouterException
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        del(self.request_mock.headers["ttl"])
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )

        def raise_error(*args):
            raise RouterException(
                "Missing TTL Header",
                status_code=400,
                response_body="Missing TTL Header",
                errno=111,
                log_exception=False,
            )

        self.wp_router_mock.route_notification.side_effect = raise_error

        def handle_finish(result):
            self.flushLoggedErrors()
            self.endpoint.set_status.assert_called_with(400, None)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_webpush_malformed_encryption(self):

        def handle_finish(value):
            err_msg = ("You're using outdated encryption; Please update "
                       "to the format described in "
                       "https://developers.google.com/web/updates/2016/"
                       "03/web-push-encryption")
            self._check_error(400, 110, message=err_msg)
        self.request_mock.headers["content-encoding"] = "aesgcm128"
        self.request_mock.headers["crypto-key"] = "content"

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_webpush_bad_routertype(self):
        fresult = dict(router_type="fred")
        self.endpoint.chid = dummy_chid
        self.request_mock.body = b"stuff"
        self.endpoint._uaid_lookup_results(fresult)

        self.endpoint.set_status.assert_called_with(400, None)
        data = self.write_mock.call_args[0][0]
        d = json.loads(data)
        eq_(d.get("errno"), 108)

    # Crypto headers should be required for Web Push...
    def test_webpush_uaid_lookup_no_crypto_headers_with_data(self):
        fresult = dict(router_type="webpush")
        frouter = self.settings.routers["webpush"]
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = dummy_chid
        self.request_mock.body = b"stuff"
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            self.endpoint.set_status.assert_called_with(400, None)

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    # ...But can be omitted for blank messages...
    def test_webpush_uaid_lookup_no_crypto_headers_without_data(self):
        fresult = dict(router_type="webpush")
        frouter = self.settings.routers["webpush"]
        frouter.route_notification.return_value = RouterResponse()
        self.endpoint.chid = dummy_chid
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
        self.endpoint.chid = dummy_chid
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
        self.endpoint.chid = dummy_chid
        self.request_mock.headers["encryption"] = "keyid=p256;dh=stuff=="
        self.request_mock.headers["crypto-key"] = (
            "keyid=spad=;dh=AQ==,p256ecdsa=Ag=;foo=\"bar==\""
        )
        self.request_mock.headers["content-encoding"] = "aes128"
        self.request_mock.body = b"\xc3\x28\xa0\xa1"
        self.endpoint._uaid_lookup_results(fresult)

        def handle_finish(value):
            calls = frouter.route_notification.mock_calls
            eq_(len(calls), 1)
            (_, (notification, _), _) = calls[0]
            eq_(notification.headers.get('encryption'),
                'keyid=p256;dh=stuff')
            eq_(notification.headers.get('crypto-key'),
                'keyid=spad;dh=AQ,p256ecdsa=Ag;foo=bar')
            eq_(notification.channel_id, dummy_chid)
            eq_(notification.data, b"wyigoQ")
            self.endpoint.set_status.assert_called_with(200)
            ok_('Padded content detected' in
                self.endpoint.write.call_args[0][0])

        self.finish_deferred.addCallback(handle_finish)
        return self.finish_deferred

    def test_init_info(self):
        d = self.endpoint._init_info()
        eq_(d["request_id"], dummy_request_id)
        h = self.request_mock.headers
        h["user-agent"] = "myself"
        d = self.endpoint._init_info()
        eq_(d["user_agent"], "myself")
        self.request_mock.remote_ip = "local1"
        d = self.endpoint._init_info()
        eq_(d["remote_ip"], "local1")
        self.request_mock.headers["x-forwarded-for"] = "local2"
        self.request_mock.headers["ttl"] = "0"
        d = self.endpoint._init_info()
        eq_(d["remote_ip"], "local2")
        eq_(d["message_ttl"], "0")
        self.request_mock.headers["authorization"] = "bearer token fred"
        d = self.endpoint._init_info()
        eq_(d["authorization"], "bearer token fred")
        self.endpoint.uaid = dummy_uaid
        eq_(self.endpoint._client_info["uaid_hash"], hasher(dummy_uaid))
        self.endpoint.chid = dummy_chid
        eq_(self.endpoint._client_info['channelID'], dummy_chid)

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
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.ap_settings.router.get_uaid.return_value = {}
        self.endpoint.ap_settings.max_data = 3
        self.endpoint.request.body = b'version=1&data=1234'

        def handle_finish(result):
            self.endpoint.set_status.assert_called_with(413, None)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, '')
        return self.finish_deferred

    def test_put_token_error(self):
        self.fernet_mock.configure_mock(**{
            'decrypt.side_effect': TypeError})
        self.endpoint.request.body = b'version=123'

        def handle_finish(value):
            self.fernet_mock.decrypt.assert_called_with(b'')
            eq_(self.endpoint.log.failure.called, True)
            self._assert_error_response(value)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, '')
        return self.finish_deferred

    def test_put_v1_token_as_v0_token(self):
        self.fernet_mock.decrypt.return_value = \
            '\xcb\n<\x0c\xe6\xf3C4:\xa8\xaeO\xf5\xab\xfbb|'

        def handle_finish(result):
            self.status_mock.assert_called_with(400, None)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, '')
        return self.finish_deferred

    def test_put_token_invalid(self):
        self.fernet_mock.configure_mock(**{
            'decrypt.side_effect': InvalidToken})
        self.endpoint.request.body = b'version=123&data=bad-token'

        def handle_finish(result):
            self.status_mock.assert_called_with(400, None)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, '')
        return self.finish_deferred

    def test_put_token_wrong(self):
        self.fernet_mock.decrypt.return_value = "123:456:789"
        self.endpoint.request.body = b'version=123'

        def handle_finish(result):
            self.status_mock.assert_called_with(400, None)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, '')
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
            self.status_mock.assert_called_with(410, None)
            self._check_error(410, 103, "")
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.version, self.endpoint.data = 789, None

        self.endpoint._token_valid(dict(uaid='123', chid=dummy_chid))
        return self.finish_deferred

    def test_put_default_router(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict()
        self.sp_router_mock.route_notification.return_value = RouterResponse()

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(200)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_put_router_with_headers(self):
        self.request_mock.headers["encryption"] = "ignored"
        self.request_mock.headers["content-encoding"] = 'text'
        self.request_mock.headers["encryption-key"] = "encKey"
        self.request_mock.body = b' '
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=200,
            router_data={},
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(200)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_put_router_needs_change(self):
        self.fernet_mock.decrypt.return_value = dummy_token
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
            self.endpoint.set_status.assert_called_with(500, None)
            assert(self.router_mock.register_user.called)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_put_router_needs_update(self):
        self.fernet_mock.decrypt.return_value = dummy_token
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
            self.endpoint.set_status.assert_called_with(503, None)
            assert(self.router_mock.register_user.called)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_put_bogus_headers(self):
        self.request_mock.headers["encryption"] = "ignored"
        self.request_mock.headers["content-encoding"] = 'text'
        self.request_mock.headers["encryption-key"] = "encKey"
        self.request_mock.headers["crypto-key"] = "fake=crypKey"
        self.request_mock.body = b' '
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=200,
            router_data={},
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(400, None)

        self.finish_deferred.addBoth(handle_finish)
        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_put_invalid_vapid_crypto_header(self):
        self.request_mock.headers["encryption"] = "ignored"
        self.request_mock.headers["content-encoding"] = 'text'
        self.request_mock.headers["authorization"] = "some auth"
        self.request_mock.headers["crypto-key"] = "crypKey"
        self.request_mock.body = b' '
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=200,
            router_data={},
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(400, None)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_put_invalid_vapid_crypto_key(self):
        self.request_mock.headers["encryption"] = "ignored"
        self.request_mock.headers["content-encoding"] = 'text'
        self.request_mock.headers["authorization"] = "invalid"
        self.request_mock.headers["crypto-key"] = "crypt=crap"
        self.request_mock.body = b' '
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=200,
            router_data={},
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(401, None)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_put_invalid_vapid_auth_header(self):
        self.request_mock.headers["encryption"] = "ignored"
        self.request_mock.headers["content-encoding"] = 'text'
        self.request_mock.headers["authorization"] = "invalid"
        self.request_mock.headers["crypto-key"] = "p256ecdsa=crap"
        self.request_mock.body = b' '
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=200,
            router_data={},
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(401, None)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_with_headers_in_response(self):
        self.fernet_mock.decrypt.return_value = dummy_token
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
        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def _gen_jwt(self, header, payload):
        sk256p = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        vk = sk256p.get_verifying_key()
        sig = jws.sign(payload, sk256p, algorithm="ES256").strip('=')
        crypto_key = utils.base64url_encode(vk.to_string()).strip('=')
        return (sig, crypto_key)

    def test_post_webpush_with_vapid_auth(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        (token, crypto_key) = self._gen_jwt(header, payload)
        auth = "Bearer %s" % token
        """ # to verify that the object is encoded correctly

            kd2 = utils.base64url_decode(crypto_key)
            vk2 = ecdsa.VerifyingKey.from_string(kd2, curve=ecdsa.NIST256p)
            res = json.loads(jws.verify(token, vk2, algorithms=["ES256"]))
            eq_(res, payload)
        """
        self.request_mock.headers["crypto-key"] = \
            "keyid=\"a1\"; key=\"foo\";p256ecdsa=\"%s\"" % crypto_key
        self.request_mock.headers["authorization"] = auth
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
        )

        def handle_finish(result, crypto_key, token):
            self.endpoint.set_status.assert_called_with(201)
            payload.update({'crypto_key': crypto_key})
            for i in payload:
                n = 'jwt_' + i
                eq_(self.endpoint._client_info.get(n), payload[i])
            self.assertTrue(result)

        self.finish_deferred.addCallback(handle_finish, crypto_key, token)
        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_decipher_public_key(self):
        # Exercise WebCrypto and other well known public key formats we may get
        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}
        (_, crypto) = self._gen_jwt(header, payload)
        crypto_key = utils.base64url_decode(crypto)

        spki_header = ('0V0\x10\x06\x04+\x81\x04p\x06\x08*'
                       '\x86H\xce=\x03\x01\x07\x03B\x00\x04')
        eq_(decipher_public_key(crypto_key), crypto_key)
        eq_(decipher_public_key('\x04' + crypto_key), crypto_key)
        eq_(decipher_public_key(spki_header + crypto_key), crypto_key)
        assert_raises(ValueError, decipher_public_key, "banana")
        crap = ''.join([random.choice('012345abcdef') for i in range(0, 64)])
        assert_raises(ValueError, decipher_public_key, '\x05' + crap)
        assert_raises(ValueError, decipher_public_key,
                      crap[:len(spki_header)] + crap)
        assert_raises(ValueError, decipher_public_key, crap[:60])

    def test_post_webpush_with_other_than_vapid_auth(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        (token, crypto_key) = self._gen_jwt(header, payload)
        auth = "Bearer other_token"
        self.request_mock.headers["crypto-key"] = "p256ecdsa=%s" % crypto_key
        self.request_mock.headers["authorization"] = auth
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
        )

        def handle_finish(result):
            self.endpoint.set_status.assert_called_with(201)
            eq_(self.endpoint._client_info.get('jwt'), None)
            self.assertTrue(result)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_with_bad_vapid_auth(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        (token, crypto_key) = self._gen_jwt(header, payload)
        crypto_key = crypto_key.strip('=')[:-2]+'ff'
        self.request_mock.headers["crypto-key"] = "p256ecdsa=%s" % crypto_key
        self.request_mock.headers["authorization"] = "Bearer " + token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
        )

        def handle_finish(result):
            self.endpoint.set_status.assert_called_with(401, None)
            eq_(self.endpoint._client_info.get('jwt'), None)
            self.assertTrue(result)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_no_sig(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        (sig, crypto_key) = self._gen_jwt(header, payload)
        sigs = sig.split('.')
        auth = "Bearer %s.%s" % (sigs[0], sigs[1])
        self.request_mock.headers["crypto-key"] = "p256ecdsa=%s" % crypto_key
        self.request_mock.headers["authorization"] = auth
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
            headers={"Location": "Somewhere"}
        )

        def handle_finish(result):
            eq_(self.endpoint._client_info.get('jwt'), None)
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(401, None)

        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_util_extract_jwt(self):
        eq_(utils.extract_jwt('a.b.c', None), {})
        eq_(utils.extract_jwt(None, 'present_but_invalid_key'), {})
        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        (sig, crypto_key) = self._gen_jwt(header, payload)
        eq_(utils.extract_jwt(sig, utils.base64url_decode(crypto_key)),
            payload)

    def test_post_webpush_bad_sig(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}

        (sig, crypto_key) = self._gen_jwt(header, payload)
        sigs = sig.split('.')
        auth = "Bearer %s.%s.%s" % (sigs[0], sigs[1], "invalid")
        self.request_mock.headers["crypto-key"] = "p256ecdsa=%s" % crypto_key
        self.request_mock.headers["authorization"] = auth
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
            headers={"Location": "Somewhere"}
        )

        def handle_finish(result):
            eq_(self.endpoint._client_info.get('jwt'), None)
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(401, None)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_bad_exp(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"

        header = {"typ": "JWT", "alg": "ES256"}
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) - 100,
                   "sub": "mailto:admin@example.com"}

        (token, crypto_key) = self._gen_jwt(header, payload)
        self.request_mock.headers["crypto-key"] = "p256ecdsa=%s" % crypto_key
        self.request_mock.headers["authorization"] = "Bearer %s" % token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
            headers={"Location": "Somewhere"}
        )

        def handle_finish(result):
            eq_(self.endpoint._client_info.get('jwt'), None)
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(401, None)

        self.finish_deferred.addCallback(handle_finish)
        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_with_auth(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.request_mock.headers["crypto-key"] = ""
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

        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_with_logged_delivered(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
            headers={"Location": "Somewhere"},
            logged_status=200
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(201)
            self.endpoint.set_header.assert_called_with(
                "Location", "Somewhere")
            args, kwargs = self.endpoint.log.info.call_args
            eq_("Successful delivery", kwargs.get('format') or args[0])
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_webpush_with_logged_stored(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=201,
            headers={"Location": "Somewhere"},
            logged_status=202
        )

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(201)
            self.endpoint.set_header.assert_called_with(
                "Location", "Somewhere")
            args, kwargs = self.endpoint.log.info.call_args
            eq_("Router miss, message stored.",
                kwargs.get('format') or args[0])
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_db_error_with_success(self):
        from autopush.router.interface import RouterException
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )

        def raise_error(*args):
            raise RouterException(
                "Provisioned throughput error",
                status_code=202,
                response_body="Success",
                log_exception=False
            )

        self.wp_router_mock.route_notification.side_effect = raise_error

        def handle_finish(result):
            self.flushLoggedErrors()
            self.endpoint.set_status.assert_called_with(202)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_post_db_error_in_routing(self):
        from autopush.router.interface import RouterException
        self.fernet_mock.decrypt.return_value = dummy_token
        self.endpoint.set_header = Mock()
        self.request_mock.headers["encryption"] = "stuff"
        self.request_mock.headers["content-encoding"] = "aes128"
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )

        def raise_error(*args):
            raise RouterException(
                "Provisioned throughput error",
                status_code=503,
                response_body="Retry Request",
                errno=201,
                log_exception=False
            )

        self.wp_router_mock.route_notification.side_effect = raise_error

        def handle_finish(result):
            self.flushLoggedErrors()
            self.endpoint.set_status.assert_called_with(503, None)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.post(None, dummy_uaid)
        return self.finish_deferred

    def test_put_db_error(self):
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.side_effect = self._throw_provisioned_error

        def handle_finish(result):
            self.assertTrue(result)
            self.endpoint.set_status.assert_called_with(503, None)
        self.finish_deferred.addCallback(handle_finish)

        self.endpoint.put(None, dummy_uaid)
        return self.finish_deferred

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        ch3 = "Access-Control-Allow-Headers"
        ch4 = "Access-Control-Expose-Headers"
        endpoint = self.endpoint
        endpoint.ap_settings.cors = False
        assert endpoint._headers.get(ch1) != "*"
        assert endpoint._headers.get(ch2) != self.CORS_METHODS
        assert endpoint._headers.get(ch3) != self.CORS_HEADERS
        assert endpoint._headers.get(ch4) != self.CORS_RESPONSE_HEADERS

        endpoint.clear_header(ch1)
        endpoint.clear_header(ch2)
        endpoint.ap_settings.cors = True
        self.endpoint.prepare()
        eq_(endpoint._headers[ch1], "*")
        eq_(endpoint._headers[ch2], self.CORS_METHODS)
        eq_(endpoint._headers[ch3], self.CORS_HEADERS)
        eq_(endpoint._headers[ch4], self.CORS_RESPONSE_HEADERS)

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
        eq_(endpoint._headers[ch2], self.CORS_METHODS)
        eq_(endpoint._headers[ch3], self.CORS_HEADERS)
        eq_(endpoint._headers[ch4], self.CORS_RESPONSE_HEADERS)

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
        eq_(endpoint._headers[ch2], self.CORS_METHODS)
        eq_(endpoint._headers[ch3], self.CORS_HEADERS)
        eq_(endpoint._headers[ch4], self.CORS_RESPONSE_HEADERS)

    def test_write_error(self):
        """ Write error is triggered by sending the app a request
        with an invalid method (e.g. "put" instead of "PUT").
        This is not code that is triggered within normal flow, but
        by the cyclone wrapper.
        """
        class testX(Exception):
            pass

        try:
            raise testX()
        except:
            exc_info = sys.exc_info()

        self.endpoint.write_error(999, exc_info=exc_info)
        self.status_mock.assert_called_with(999)
        self.assertTrue(self.endpoint.log.called)

    def test_write_error_no_exc(self):
        """ Write error is triggered by sending the app a request
        with an invalid method (e.g. "put" instead of "PUT").
        This is not code that is triggered within normal flow, but
        by the cyclone wrapper.
        """
        self.endpoint.write_error(999)
        self.status_mock.assert_called_with(999)
        self.assertTrue(self.endpoint.log.called)

    def _assert_error_response(self, result):
        self.status_mock.assert_called_with(500, None)

    def test_padding(self):
        # Some values can't be padded and still decode.
        assert_raises(TypeError,
                      utils.base64url_decode,
                      "a===")
        eq_(utils.base64url_decode("ab=="), "\x69")
        eq_(utils.base64url_decode("abc="), "\x69\xb7")
        eq_(utils.base64url_decode("abcd"), "\x69\xb7\x1d")

    def test_v2_padded_fernet_decode(self):
        # Generate a previously valid URL that would cause the #466 issue
        self.endpoint.ap_settings.fernet = self.old_fernet
        # stripped, but valid crypto_key
        dummy_key = ("BHolMkL36ucQsRe_0KRS70JyHB55H4C5Igv2YQEVNzCILN"
                     "nedxFHSPtzI4KhzNtN2YPqHe7-mWW6_uvaIc5yEDk")
        # Generate an endpoint, since the fernet key is not locked during
        # testing.
        while True:
            ep = self.endpoint.ap_settings.make_endpoint(
                dummy_uaid,
                dummy_chid,
                dummy_key)
            token = ep.split("/")[-1]
            if len(token) % 4:
                break
        reply = self.settings.parse_endpoint(token, "v2",
                                             "p256ecdsa=" + dummy_key)
        eq_(reply, {'public_key': base64.urlsafe_b64decode(
                    utils.repad(dummy_key)),
                    'chid': dummy_chid.replace('-', ''),
                    'uaid': dummy_uaid.replace('-', '')})

    def test_parse_endpoint(self):
        v0_valid = dummy_uaid + ":" + dummy_chid
        uaid_strip = dummy_uaid.replace('-', '')
        chid_strip = dummy_chid.replace('-', '')
        uaid_dec = uaid_strip.decode('hex')
        chid_dec = chid_strip.decode('hex')
        v1_valid = uaid_dec + chid_dec
        raw_pub_key = uuid.uuid4().bytes
        pub_key = utils.base64url_encode(raw_pub_key)
        crypto_key = "p256ecdsa=" + pub_key
        v2_valid = sha256(raw_pub_key).digest()
        v2_invalid = sha256(uuid.uuid4().hex).digest()
        # v0 good
        self.fernet_mock.decrypt.return_value = v0_valid
        tokens = self.settings.parse_endpoint('/valid')
        eq_(tokens, dict(uaid=dummy_uaid, chid=dummy_chid, public_key=None))

        # v0 bad
        self.fernet_mock.decrypt.return_value = v1_valid
        with assert_raises(InvalidTokenException) as cx:
            self.settings.parse_endpoint('/invalid')
        eq_(cx.exception.message, 'Corrupted push token')

        self.fernet_mock.decrypt.return_value = v1_valid[:30]
        with assert_raises(InvalidTokenException) as cx:
            self.settings.parse_endpoint('invalid', 'v1')
        eq_(cx.exception.message, 'Corrupted push token')

        self.fernet_mock.decrypt.return_value = v1_valid
        tokens = self.settings.parse_endpoint('valid', 'v1')
        eq_(tokens, dict(uaid=uaid_strip, chid=chid_strip, public_key=None))

        self.fernet_mock.decrypt.return_value = v1_valid + v2_valid
        tokens = self.settings.parse_endpoint('valid', 'v2', crypto_key)
        eq_(tokens,
            dict(uaid=uaid_strip, chid=chid_strip, public_key=raw_pub_key))

        self.fernet_mock.decrypt.return_value = v1_valid + "invalid"
        with assert_raises(InvalidTokenException) as cx:
            self.settings.parse_endpoint('invalid', 'v2', crypto_key)
        eq_(cx.exception.message, "Corrupted push token")

        self.fernet_mock.decrypt.return_value = v1_valid + v2_valid
        with assert_raises(InvalidTokenException) as cx:
            self.settings.parse_endpoint('invalid', 'v2',
                                         "p256ecdsa="+pub_key[:12])
        eq_(cx.exception.message, "Key mismatch")

        self.fernet_mock.decrypt.return_value = v1_valid + v2_invalid
        with assert_raises(InvalidTokenException) as cx:
            self.settings.parse_endpoint('invalid', 'v2')
        eq_(cx.exception.message, "Invalid key data")

        self.fernet_mock.decrypt.return_value = v1_valid + v2_invalid
        with assert_raises(InvalidTokenException) as cx:
            self.settings.parse_endpoint('invalid', 'v2', crypto_key)
        eq_(cx.exception.message, "Key mismatch")

    def test_make_endpoint(self):

        def echo(val):
            return val.encode('hex')

        # make a v1 endpoint:
        self.fernet_mock.encrypt = echo
        strip_uaid = dummy_uaid.replace('-', '')
        strip_chid = dummy_chid.replace('-', '')
        dummy_key = "RandomKeyString"
        sha = sha256(dummy_key).hexdigest()
        ep = self.settings.make_endpoint(dummy_uaid, dummy_chid)
        eq_(ep, 'http://localhost/wpush/v1/' + strip_uaid + strip_chid)
        ep = self.settings.make_endpoint(dummy_uaid, dummy_chid,
                                         utils.base64url_encode(dummy_key))
        eq_(ep, 'http://localhost/wpush/v2/' + strip_uaid + strip_chid + sha)


CORS_HEAD = "POST,PUT,DELETE"


class RegistrationTestCase(unittest.TestCase):

    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        settings = endpoint.RegistrationHandler.ap_settings =\
            AutopushSettings(
                hostname="localhost",
                statsd_host=None,
                bear_hash_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=',
            )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.router_mock.register_user = Mock()
        self.router_mock.register_user.return_value = (True, {}, {})
        settings.routers["test"] = self.router_mock

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.reg = endpoint.RegistrationHandler(Application(),
                                                self.request_mock,
                                                ap_settings=settings)

        self.status_mock = self.reg.set_status = Mock()
        self.write_mock = self.reg.write = Mock()
        self.auth = ("Bearer %s" %
                     generate_hash(self.reg.ap_settings.bear_hash_key[0],
                                   dummy_uaid))

        d = self.finish_deferred = Deferred()
        self.reg.finish = lambda: d.callback(True)
        self.settings = settings

    def test_base_tags(self):
        self.reg._base_tags = []
        self.reg.request = Mock(headers={'user-agent': 'test'},
                                host='example.com:8080')
        tags = self.reg.base_tags()
        eq_(tags, ['user_agent:test', 'host:example.com:8080'])

    def _check_error(self, code, errno, error, message=None):
        d = json.loads(self.write_mock.call_args[0][0])
        eq_(d.get("code"), code)
        eq_(d.get("errno"), errno)
        eq_(d.get("error"), error)

    def test_init_info(self):
        h = self.request_mock.headers
        h["user-agent"] = "myself"
        d = self.reg._init_info()
        eq_(d["user_agent"], "myself")
        self.request_mock.remote_ip = "local1"
        d = self.reg._init_info()
        eq_(d["remote_ip"], "local1")
        self.request_mock.headers["x-forwarded-for"] = "local2"
        d = self.reg._init_info()
        eq_(d["remote_ip"], "local2")

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
            eq_(call_arg["uaid"], dummy_uaid.replace('-', ''))
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")
            ok_("secret" in call_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.post("simplepush", "")
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_gcm(self, *args):
        from autopush.router.gcm import GCMRouter
        sids = {"182931248179192": {"auth": "aailsjfilajdflijdsilfjsliaj"}}
        gcm = GCMRouter(self.settings,
                        {"dryrun": True, "senderIDs": sids})
        self.reg.ap_settings.routers["gcm"] = gcm
        self.reg.request.body = json.dumps(dict(
            channelID=dummy_chid,
            token="token",
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
            eq_(call_arg["uaid"], dummy_uaid.replace('-', ''))
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")
            calls = self.reg.ap_settings.router.register_user.call_args
            call_args = calls[0][0]
            eq_(True, has_connected_this_month(call_args))
            ok_("secret" in call_arg)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.post("gcm", "182931248179192")
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_invalid_args(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="invalid",
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
            type="invalid",
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
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(router_type="test", uaid=dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_bad_uaid(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=dummy_chid,
            data={},
        ))

        def handle_finish(value):
            self._check_error(401, 109, "Unauthorized")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(router_type="simplepush", uaid='invalid')
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_uaid))
    def test_post_bad_params(self, *args):
        self.reg.request.body = json.dumps(dict(
            channelID=dummy_chid,
        ))

        def handle_finish(value):
            self._check_error(401, 109, 'Unauthorized')

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = "Bearer Invalid"
        self.reg.post(router_type="simplepush",
                      uaid=dummy_uaid, chid=dummy_chid)
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
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(router_type="simplepush", uaid=dummy_uaid,
                      chid=dummy_chid)
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
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(router_type="simplepush", uaid=dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_post_with_app_server_key(self, *args):
        dummy_key = "RandomKeyString"
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            key=utils.base64url_encode(dummy_key),
            data={},
        ))

        def mock_encrypt(cleartext):
            eq_(len(cleartext), 64)
            # dummy_uaid
            eq_(cleartext[0:16],
                'abad1dea00000000aabbccdd00000000'.decode('hex'))
            # dummy_chid
            eq_(cleartext[16:32],
                'deadbeef00000000decafbad00000000'.decode('hex'))
            # sha256(dummy_key).digest()
            eq_(cleartext[32:],
                ('47aedd050b9e19171f0fa7b8b65ca670'
                '28f0bc92cd3f2cd3682b1200ec759007').decode('hex'))
            return 'abcd123'
        self.fernet_mock.configure_mock(**{
            'encrypt.side_effect': mock_encrypt,
        })
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["channelID"], dummy_chid)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v2/abcd123")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(router_type="simplepush", uaid=dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_put(self, *args):
        data = dict(token="some_token")
        self.router_mock.register = Mock()
        self.router_mock.register.return_value = data
        self.reg.request.body = json.dumps(data)

        def handle_finish(value):
            self.reg.write.assert_called_with({})
            self.router_mock.register.assert_called_with(dummy_uaid, data)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.put(router_type='test', uaid=dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_put_bad_auth(self, *args):
        self.reg.request.headers["Authorization"] = "Fred Smith"

        def handle_finish(value):
            self._check_error(401, 109, "Unauthorized")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(uaid=dummy_uaid)
        return self.finish_deferred

    @patch('uuid.uuid4', return_value=uuid.UUID(dummy_chid))
    def test_put_bad_arguments(self, *args):
        self.reg.request.headers["Authorization"] = self.auth
        data = dict(token="some_token")
        self.reg.request.body = json.dumps(dict(
            type="test",
            data=data,
        ))

        def handle_finish(value):
            self._check_error(400, 108, "Bad Request")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(uaid=dummy_uaid)
        return self.finish_deferred

    def test_delete_chid(self):
        messages = self.reg.ap_settings.message
        messages.register_channel(dummy_uaid, dummy_chid)
        messages.store_message(
            dummy_uaid,
            dummy_chid,
            "1",
            10000)
        chid2 = str(uuid.uuid4())
        messages.register_channel(dummy_uaid, chid2)
        messages.store_message(
            dummy_uaid,
            chid2,
            "2",
            10000)
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value, chid2):
            ml = messages.fetch_messages(dummy_uaid)
            cl = messages.all_channels(dummy_uaid)
            eq_(len(ml), 1)
            eq_((True, set([chid2])), cl)
            messages.delete_user(dummy_uaid)

        self.finish_deferred.addCallback(handle_finish, chid2)
        self.reg.delete("simplepush", "test", dummy_uaid, dummy_chid)
        return self.finish_deferred

    def test_delete_bad_chid(self):
        messages = self.reg.ap_settings.message
        messages.register_channel(dummy_uaid, dummy_chid)
        messages.store_message(
            dummy_uaid,
            dummy_chid,
            "1",
            10000)
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self._check_error(410, 106, "")
            messages.delete_user(dummy_uaid)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete("test", "test", dummy_uaid, "invalid")
        return self.finish_deferred

    def test_delete_uaid(self):
        messages = self.reg.ap_settings.message
        chid2 = str(uuid.uuid4())
        messages.store_message(
            dummy_uaid,
            dummy_chid,
            "1",
            10000)
        messages.store_message(
            dummy_uaid,
            chid2,
            "2",
            10000)
        self.reg.ap_settings.router.drop_user = Mock()
        self.reg.ap_settings.router.drop_user.return_value = True

        def handle_finish(value, chid2):
            ml = messages.fetch_messages(dummy_uaid)
            eq_(len(ml), 0)
            # Note: Router is mocked, so the UAID is never actually
            # dropped. Normally, this should messages.all_channels
            # would come back as empty
            ok_(self.reg.ap_settings.router.drop_user.called)
            eq_(self.reg.ap_settings.router.drop_user.call_args_list[0][0],
                (dummy_uaid,))

        self.finish_deferred.addCallback(handle_finish, chid2)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.delete("simplepush", "test", dummy_uaid)
        return self.finish_deferred

    def test_delete_bad_uaid(self):
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self.reg.set_status.assert_called_with(401, None)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete("test", "test", "invalid")
        return self.finish_deferred

    def test_delete_orphans(self):
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self.reg.set_status.assert_called_with(410, None)

        self.router_mock.drop_user = Mock()
        self.router_mock.drop_user.return_value = False
        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete("test", "test", dummy_uaid)
        return self.finish_deferred

    def test_delete_bad_auth(self, *args):
        self.reg.request.headers["Authorization"] = "Invalid"

        def handle_finish(value):
            self.reg.set_status.assert_called_with(401, None)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete("test", "test", dummy_uaid)
        return self.finish_deferred

    def test_delete_bad_router(self):
        self.reg.request.headers['Authorization'] = self.auth

        def handle_finish(value):
            self.reg.set_status.assert_called_with(400, None)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete("invalid", "test", dummy_uaid)
        return self.finish_deferred

    def test_validate_auth(self):
        eq_(False, self.reg._validate_auth(dummy_uaid))
        self.reg.request.headers['Authorization'] = self.auth
        eq_(True, self.reg._validate_auth(dummy_uaid))
        self.reg.ap_settings.bear_hash_key = []
        eq_(True, self.reg._validate_auth(dummy_uaid))
