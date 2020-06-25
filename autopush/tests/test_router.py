# -*- coding: utf-8 -*-
import copy
import decimal
import json
import socket
import ssl
import time
import uuid
from unittest import TestCase

import hyper.tls
import pyfcm
import pytest
import treq
from botocore.exceptions import ClientError
from hyper.http20.exceptions import HTTP20Error
from mock import Mock, PropertyMock, patch
from oauth2client.service_account import ServiceAccountCredentials
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.error import (ConnectError, ConnectionRefusedError,
                                    TimeoutError)
from twisted.python.failure import Failure
from twisted.trial import unittest
from twisted.web.client import Agent
from twisted.web.http_headers import Headers

from autopush.config import AutopushConfig
from autopush.db import (
    Message
)
from autopush.exceptions import ItemNotFound, RouterException
from autopush.metrics import SinkMetrics
from autopush.router import (APNSRouter, FCMRouter, FCMv1Router, GCMRouter,
                             WebPushRouter, fcmv1client, gcmclient)
from autopush.router.interface import IRouter, RouterResponse
from autopush.tests import MockAssist
from autopush.tests.support import test_db
from autopush.utils import WebPushNotification


class RouterInterfaceTestCase(TestCase):
    def test_not_implemented(self):
        with pytest.raises(NotImplementedError):
            IRouter(None, None)

        def init(self, conf, router_conf):
            pass
        IRouter.__init__ = init
        ir = IRouter(None, None)
        with pytest.raises(NotImplementedError):
            ir.register("uaid", {}, "")
        with pytest.raises(NotImplementedError):
            ir.route_notification("uaid", {})
        with pytest.raises(NotImplementedError):
            ir.amend_endpoint_response({}, {})


# FOR LEGACY REASONS, CHANNELID MUST BE IN HEX FORMAT FOR BRIDGE PUBLICATION
# AND REGISTRATION
dummy_chid = uuid.uuid4().hex
dummy_uaid = str(uuid.uuid4())


class APNSRouterTestCase(unittest.TestCase):

    def _waitfor(self, func):
        times = 0
        while not func():  # pragma: nocover
            time.sleep(1)
            times += 1
            if times > 9:
                break

    @patch('autopush.router.apns2.HTTP20Connection',
           spec=hyper.HTTP20Connection)
    @patch('hyper.tls', spec=hyper.tls)
    def setUp(self, mt, mc):
        from twisted.logger import Logger
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        apns_config = {
            'firefox':
                {'cert': 'fake.cert',
                 'key': 'fake.key',
                 'topic': 'com.example.SomeApp',
                 'max_connections': 2,
                 }
        }
        self.mock_connection = mc
        mc.return_value = mc
        self.metrics = metrics = Mock(spec=SinkMetrics)
        self.router = APNSRouter(conf, apns_config, metrics)
        self.mock_response = Mock()
        self.mock_response.status = 200
        mc.get_response.return_value = self.mock_response
        # toss the existing connection
        try:
            self.router.apns['firefox'].connections.pop()
        except IndexError:  # pragma nocover
            pass
        self.router.apns['firefox'].connections.append(
            self.mock_connection
        )
        self.router.apns['firefox'].log = Mock(spec=Logger)
        self.headers = {"content-encoding": "aesgcm",
                        "encryption": "test",
                        "encryption-key": "test"}
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=200,
            message_id=10,
        )
        self.notif.cleanup_headers()
        self.router_data = dict(router_data=dict(token="connect_data",
                                                 rel_channel="firefox"))

    def test_register(self):
        router_data = {"token": "connect_data"}
        self.router.register("uaid", router_data=router_data,
                             app_id="firefox")
        assert router_data == {"rel_channel": "firefox",
                               "token": "connect_data"}

    def test_extended_register(self):
        router_data = {"token": "connect_data",
                       "aps": {"foo": "bar",
                               "gorp": "baz"}}
        self.router.register("uaid", router_data=router_data,
                             app_id="firefox")
        assert router_data == {
            "rel_channel": "firefox", "token": "connect_data",
            "aps": {"foo": "bar", "gorp": "baz"}}

    def test_register_bad(self):
        with pytest.raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="firefox")

    def test_register_bad_channel(self):
        with pytest.raises(RouterException):
            self.router.register(
                "uaid",
                router_data={"token": "connect_data"},
                app_id="unknown")

    @inlineCallbacks
    def test_connection_error(self):
        from hyper.http20.exceptions import ConnectionError

        def raiser(*args, **kwargs):
            raise ConnectionError("oops")

        self.router.apns['firefox'].connections[1].request = Mock(
            side_effect=raiser)

        with pytest.raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)

        assert ex.value.response_body == ('APNS returned an error '
                                          'processing request')
        assert ex.value.status_code == 502
        self.flushLoggedErrors()

    @inlineCallbacks
    def test_connection_fail_error(self):

        def raiser(*args, **kwargs):
            error = socket.error()
            error.errno = socket.errno.EPIPE
            raise error

        self.router.apns['firefox'].connections[1].request = Mock(
            side_effect=raiser)

        with pytest.raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)

        assert ex.value.response_body == "APNS returned an error processing " \
                                         "request"
        assert ex.value.status_code == 502
        self.flushLoggedErrors()

    @inlineCallbacks
    def test_route_notification(self):
        result = yield self.router.route_notification(self.notif,
                                                      self.router_data)
        yield self._waitfor(lambda:
                            self.mock_connection.request.called is True)

        assert isinstance(result, RouterResponse)
        assert self.mock_connection.request.called
        body = self.mock_connection.request.call_args[1]
        body_json = json.loads(body['body'])
        assert 'chid' in body_json
        # The ChannelID is a UUID4, and unpredictable.
        del(body_json['chid'])
        assert body_json == {
            "body": "q60d6g",
            "enc": "test",
            "ver": 10,
            "aps": {
                "mutable-content": 1,
                "alert": {
                    "loc-key": "SentTab.NoTabArrivingNotification.body",
                    "title-loc-key": "SentTab.NoTabArrivingNotification.title",
                },
            },
            "enckey": "test",
            "con": "aesgcm",
        }

    @inlineCallbacks
    def test_route_notification_complex(self):
        router_data = dict(
            router_data=dict(token="connect_data",
                             rel_channel="firefox",
                             aps=dict(string="String",
                                      array=['a', 'b', 'c'],
                                      number=decimal.Decimal(4))))
        result = yield self.router.route_notification(self.notif,
                                                      router_data)
        yield self._waitfor(lambda:
                            self.mock_connection.request.called is True)
        assert isinstance(result, RouterResponse)
        assert self.mock_connection.request.called
        body = self.mock_connection.request.call_args[1]
        body_json = json.loads(body['body'])
        assert body_json['aps']['number'] == 4
        assert body_json['aps']['string'] == 'String'

    @inlineCallbacks
    def test_route_low_priority_notification(self):
        """low priority and empty apns_ids are not yet used, but may feature
        when priorty work is done."""
        apns2 = self.router.apns['firefox']
        exp = int(time.time()+300)
        yield apns2.send("abcd0123", {}, 'apnsid', priority=False, exp=exp)
        yield self._waitfor(lambda:
                            self.mock_connection.request.called is True)
        assert self.mock_connection.request.called
        body = self.mock_connection.request.call_args[1]
        headers = body['headers']
        assert headers == {
            'apns-expiration': str(exp),
            'apns-topic': 'com.example.SomeApp',
            'apns-priority': '5',
            'apns-id': 'apnsid'}

    @inlineCallbacks
    def test_bad_send(self):
        self.mock_response.status = 400
        self.mock_response.read.return_value = json.dumps({'reason': 'boo'})
        with pytest.raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)
        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 502
        assert str(ex.value) == 'APNS Transmit Error 400:boo'
        assert ex.value.response_body == (
            'APNS returned an error processing request')

    @inlineCallbacks
    def test_aaaa_fail_send(self):
        def throw(*args, **kwargs):
            raise HTTP20Error("oops")

        self.router.apns['firefox'].connections[0].request.side_effect = throw
        with pytest.raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)
        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 502
        assert str(ex.value) == "oops"
        assert ex.value.response_body == 'APNS returned an error ' \
                                         'processing request'
        assert self.metrics.increment.called
        assert self.metrics.increment.call_args[0][0] == \
            'notification.bridge.connection.error'
        self.flushLoggedErrors()

    @inlineCallbacks
    def test_fail_send_bad_write_retry(self):
        def throw(*args, **kwargs):
            raise ssl.SSLError(
                ssl.SSL_ERROR_SSL,
                "[SSL: BAD_WRITE_RETRY] bad write retry"
            )

        self.router.apns['firefox'].connections[0].request.side_effect = throw
        with pytest.raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)
        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 502
        assert str(ex.value) == "[SSL: BAD_WRITE_RETRY] bad write retry"
        assert ex.value.response_body == 'APNS returned an error ' \
                                         'processing request'
        assert self.metrics.increment.called
        assert self.metrics.increment.call_args[0][0] == \
            'notification.bridge.connection.error'
        self.flushLoggedErrors()

    def test_too_many_connections(self):
        rr = self.router.apns['firefox']
        with pytest.raises(RouterException) as ex:
            while True:
                rr._get_connection()

        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 503
        assert str(ex.value) == "Too many APNS requests, increase pool from 2"
        assert ex.value.response_body == "APNS busy, please retry"

    def test_apns_amend(self):
        resp = {"key": "value"}
        expected = resp.copy()
        self.router.amend_endpoint_response(resp, {})
        assert resp == expected

    def test_route_crypto_key(self):
        headers = {"content-encoding": "aesgcm",
                   "encryption": "test",
                   "crypto-key": "test"}
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=headers,
            ttl=200,
            message_id=10,
        )
        self.notif.cleanup_headers()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            assert result.logged_status == 200
            assert "TTL" in result.headers
            assert self.mock_connection.called

        d.addCallback(check_results)
        return d


class GCMRouterTestCase(unittest.TestCase):

    def setUp(self):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.gcm_config = {'max_data': 32,
                           'ttl': 60,
                           'senderIDs': {'test123':
                                         {"auth": "12345678abcdefg"}},
                           'endpoint': 'gcm-http.googleapis.com/gcm/send'}
        self._m_request = Deferred()
        self.response = Mock(spec=treq.response._Response)
        self.response.code = 200
        self.response.headers = Headers()
        self._m_resp_text = Deferred()
        self.response.text.return_value = self._m_resp_text
        self.response.content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 1,
            "failure": 0,
            "canonical_ids": 0,
            "results": [
                {
                    "message_id": "0:1510011451922224%7a0e7efbaab8b7cc"
                }
            ]
        })
        self.gcmclient = gcmclient.GCM(api_key="SomeKey")
        self.gcmclient._sender = Mock()
        self.gcmclient._sender.return_value = self._m_request
        self.router = GCMRouter(conf, self.gcm_config, SinkMetrics())
        self.router.gcmclients['test123'] = self.gcmclient
        self.headers = {"content-encoding": "aesgcm",
                        "encryption": "test",
                        "encryption-key": "test"}
        # Payloads are Base64-encoded.
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=200,
            message_id=10,
        )
        self.notif.cleanup_headers()
        self.router_data = dict(
            router_data=dict(
                token="connect_data",
                creds=dict(senderID="test123", auth="12345678abcdefg")))

    def _set_content(self, content=None):
        if content is None:
            content = self.response.content
        self._m_resp_text.callback(content)
        self._m_request.callback(self.response)

    def _check_error_call(self, exc, code, response=None, errno=None):
        assert isinstance(exc, RouterException)
        assert exc.status_code == code
        if errno is not None:
            assert exc.errno == errno
        assert self.gcmclient._sender.called
        if response:
            assert response in exc.response_body
        self.flushLoggedErrors()

    def test_init(self):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        with pytest.raises(IOError):
            GCMRouter(conf, {"senderIDs": {},
                             "endpoint": "gcm-http.googleapis.com/gcm/send"},
                      SinkMetrics())

    def test_register(self):
        router_data = {"token": "test123"}
        self.router.register("uaid", router_data=router_data, app_id="test123")
        # Check the information that will be recorded for this user
        assert router_data == {
            "token": "test123",
            "creds": {"senderID": "test123",
                      "auth": "12345678abcdefg"}}

    def test_register_bad(self):
        with pytest.raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="")
        with pytest.raises(RouterException):
            self.router.register("uaid", router_data={}, app_id=None)
        with pytest.raises(RouterException):
            self.router.register(
                "uaid",
                router_data={"token": "abcd1234"},
                app_id="invalid123")

    def test_route_notification(self):
        self.router.gcmclients['test123'] = self.gcmclient
        d = self.router.route_notification(self.notif, self.router_data)
        self._set_content()

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.gcmclient._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.gcmclient._sender.call_args[1]['data'])
            data = payload['data']
            assert data['body'] == 'q60d6g'
            assert data['enc'] == 'test'
            assert data['chid'] == dummy_chid
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
        d.addCallback(check_results)
        return d

    def test_ttl_none(self):
        self.router.gcmclients['test123'] = self.gcmclient
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=None
        )
        self.notif.cleanup_headers()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            assert result.logged_status == 200
            assert "TTL" in result.headers
            assert self.gcmclient._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.gcmclient._sender.call_args[1]['data'])
            data = payload['data']
            assert data['body'] == 'q60d6g'
            assert data['enc'] == 'test'
            assert data['chid'] == dummy_chid
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
            # use the defined min TTL
            assert payload['time_to_live'] == 60
        d.addCallback(check_results)
        return d

    def test_ttl_high(self):
        self.router.gcmclients['test123'] = self.gcmclient
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=5184000
        )
        self.notif.cleanup_headers()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.gcmclient._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.gcmclient._sender.call_args[1]['data'])
            data = payload['data']
            assert data['body'] == 'q60d6g'
            assert data['enc'] == 'test'
            assert data['chid'] == dummy_chid
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
            # use the defined min TTL
            assert payload['time_to_live'] == 2419200
        d.addCallback(check_results)
        return d

    def test_long_data(self):
        self.router.gcmclients['test123'] = self.gcmclient
        bad_notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="\x01abcdefghijklmnopqrstuvwxyz0123456789",
            headers=self.headers,
            ttl=200
        )
        self._set_content()

        with pytest.raises(RouterException) as ex:
            self.router.route_notification(bad_notif, self.router_data)

        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 413
        assert ex.value.errno == 104

    def test_route_crypto_notification(self):
        del(self.notif.headers['encryption_key'])
        self.notif.headers['crypto_key'] = 'crypto'
        self._set_content()

        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.gcmclient._sender.called
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_auth_error(self):
        self.response.code = 401
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error", 901)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_other_error(self):
        self._m_request.errback(Failure(Exception))
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error")
        d.addBoth(check_results)
        return d

    def test_router_notification_connection_error(self):

        self.router.gcmclients['test123'] = self.gcmclient
        self._m_request.errback(Failure(ConnectError("oh my!")))
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 502, "Server error", 902)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_id_change(self):
        self.response.content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 1,
            "failure": 0,
            "canonical_ids": 1,
            "results": [
                {
                    "message_id": "0:1510011451922224%7a0e7efbaab8b7cc",
                    "registration_id": "new",
                }
            ]
        })
        self.router.metrics = Mock()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict(token="new")
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:reregister']
            assert self.gcmclient._sender.called
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_not_regged(self):
        self.response.content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 1,
            "failure": 1,
            "canonical_ids": 0,
            "results": [
                {
                    "error": "NotRegistered"
                }
            ]
        })
        self.router.metrics = Mock()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict()
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:unregistered']
            assert self.gcmclient._sender.called
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_failed_items(self):
        self.response.content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 1,
            "failure": 1,
            "canonical_ids": 0,
            "results": [
                {
                    "error": "InvalidRegistration"
                }
            ]
        })
        self.router.metrics = Mock()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert self.router.metrics.increment.called
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:failure']
            assert str(fail.value) == 'GCM unable to deliver'
            self._check_error_call(fail.value, 410)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_needs_retry(self):
        self.response.headers.addRawHeader('Retry-After', "123")
        self.response.code = 500
        self.response.content = ""
        self.router.metrics = Mock()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert self.router.metrics.increment.called
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:retry']
            assert str(fail.value) == 'GCM failure to deliver, retry'
            self._check_error_call(fail.value, 503)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_no_auth(self):
        self._set_content()
        with pytest.raises(RouterException) as ex:
            self.router.route_notification(self.notif,
                                           {"router_data": {"token": "abc"}})

        assert isinstance(ex.value, RouterException)
        assert str(ex.value) == "Server error"
        assert ex.value.status_code == 500
        assert ex.value.errno == 900

    def test_router_timeout(self):
        self.router.metrics = Mock()

        def timeout(*args, **kwargs):
            self._m_request.errback(Failure(TimeoutError()))
            return self._m_request

        self.gcmclient._sender.side_effect = timeout
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert self.router.metrics.increment.called
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:timeout']

        d.addBoth(check_results)
        return d

    def test_router_unknown_err(self):
        self.router.metrics = Mock()

        def timeout(*args, **kwargs):
            self._m_request.errback(Failure(Exception()))
            return self._m_request

        self.gcmclient._sender.side_effect = timeout
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert isinstance(fail.value, RouterException)

        d.addBoth(check_results)
        return d

    def test_gcm_amend(self):
        router_data = {"token": "test123"}
        self.router.register("uaid", router_data=router_data,
                             app_id="test123")
        resp = {"key": "value"}
        self.router.amend_endpoint_response(
            resp, self.router_data.get('router_data'))
        assert {"key": "value", "senderid": "test123"} == resp

    def test_register_invalid_token(self):
        with pytest.raises(RouterException):
            self.router.register(
                uaid="uaid",
                router_data={"token": "invalid"},
                app_id="invalid")


class FCMv1RouterTestCase(unittest.TestCase):
    def setUp(self):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.fcm_config = {'max_data': 32,
                           'ttl': 60,
                           'version': 1,
                           'dryrun': False,
                           'collapsekey': 'simplepush',
                           'creds': {
                               'fir-bridgetest': {
                                   'projectid': 'fir-bridgetest',
                                   # We specify 'None' here because we're
                                   # going to mock out the actual service
                                   # credential service.
                                   # This should be a path to a valid service
                                   # credential JSON file.
                                   'auth': None
                               }}}
        self._m_request = Deferred()
        self.response = Mock(spec=treq.response._Response)
        self.response.code = 200
        self.response.headers = Headers()
        self._m_resp_text = Deferred()
        self.response.text.return_value = self._m_resp_text
        self.response.content = json.dumps(
            {u'name': (u'projects/fir-bridgetest/messages/'
                       u'0:1510011451922224%7a0e7efbaab8b7cc')})
        self.client = fcmv1client.FCMv1(project_id="fir-bridgetest")
        self.client._sender = Mock()
        self.client.svc_cred = Mock(spec=ServiceAccountCredentials)
        self.client._sender.return_value = self._m_request
        self.router = FCMv1Router(conf, self.fcm_config, SinkMetrics())
        self.router.clients = {"fir-bridgetest": self.client}
        self.headers = {"content-encoding": "aesgcm",
                        "encryption": "test",
                        "encryption-key": "test"}
        # Payloads are Base64-encoded.
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=200,
            message_id=10,
        )
        self.notif.cleanup_headers()
        self.router_data = dict(
            router_data=dict(
                token="connect_data",
                app_id="fir-bridgetest")
        )

    def _set_content(self, content=None):
        if content is None:
            content = self.response.content
        self._m_resp_text.callback(content)
        self._m_request.callback(self.response)

    def _check_error_call(self, exc, code, response=None, errno=None):
        assert isinstance(exc, RouterException)
        assert exc.status_code == code
        if errno is not None:
            assert exc.errno == errno
        assert self.client._sender.called
        if response:
            assert response in exc.response_body
        self.flushLoggedErrors()

    @patch("autopush.router.fcmv1client.ServiceAccountCredentials")
    def test_bad_init(self, m_sac):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        m_sac.from_json_keyfile_name.side_effect = IOError
        with pytest.raises(IOError):
            bad_router_conf = copy.deepcopy(self.fcm_config)
            bad_router_conf["creds"]["fir-bridgetest"]["auth"] = "invalid_path"
            FCMv1Router(conf,
                        bad_router_conf,
                        SinkMetrics())

    def test_register(self):
        router_data = {"token": "registration_data"}
        self.router.register(
            "uaid", router_data=router_data, app_id="fir-bridgetest")
        # Check the information that will be recorded for this user
        assert "fir-bridgetest" in self.router.clients
        assert router_data["app_id"] == "fir-bridgetest"

    def test_register_bad(self):
        with pytest.raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="")
        with pytest.raises(RouterException):
            self.router.register("uaid", router_data={}, app_id=None)
        with pytest.raises(RouterException):
            self.router.register(
                "uaid",
                router_data={"token": "abcd1234"},
                app_id="invalid123")

    def test_route_notification(self):
        d = self.router.route_notification(self.notif, self.router_data)
        self._set_content()

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.client._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.client._sender.call_args[1]['data'])
            data = payload['message']['android']['data']
            assert data['body'] == 'q60d6g'
            assert data['enc'] == 'test'
            assert data['chid'] == dummy_chid
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
        d.addCallback(check_results)
        return d

    def test_ttl_none(self):
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=None
        )
        self.notif.cleanup_headers()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            assert result.logged_status == 200
            assert "TTL" in result.headers
            assert self.client._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.client._sender.call_args[1]['data'])
            data = payload['message']['android']['data']
            assert data['body'] == 'q60d6g'
            assert data['enc'] == 'test'
            assert data['chid'] == dummy_chid
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
            # use the defined min TTL
            assert payload['message']['android']['ttl'] == "60s"
        d.addCallback(check_results)
        return d

    def test_ttl_high(self):
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=5184000
        )
        self.notif.cleanup_headers()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.client._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.client._sender.call_args[1]['data'])
            data = payload['message']['android']['data']
            assert data['body'] == 'q60d6g'
            assert data['enc'] == 'test'
            assert data['chid'] == dummy_chid
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
            # use the defined min TTL
            assert payload['message']['android']['ttl'] == "2419200s"
        d.addCallback(check_results)
        return d

    def test_long_data(self):
        bad_notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="\x01abcdefghijklmnopqrstuvwxyz0123456789",
            headers=self.headers,
            ttl=200
        )
        self._set_content()

        with pytest.raises(RouterException) as ex:
            self.router.route_notification(bad_notif, self.router_data)

        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 413
        assert ex.value.errno == 104

    def test_route_crypto_notification(self):
        del(self.notif.headers['encryption_key'])
        self.notif.headers['crypto_key'] = 'crypto'
        self._set_content()

        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.client._sender.called
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_auth_error(self):
        self.response.code = 401
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error", 901)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_not_found_error(self):
        self.response.code = 404
        self._set_content(json.dumps(
            {"error":
                {"code": 404,
                 "status": "NOT_FOUND",
                 "message": "Requested entity was not found."
                 }
             }))
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 404,
                                   "FCM Recipient no longer available", 106)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_other_error(self):
        self._m_request.errback(Failure(Exception))
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error")
        d.addBoth(check_results)
        return d

    def test_router_notification_connection_error(self):

        self._m_request.errback(Failure(ConnectError("oh my!")))
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 502, "Server error", 902)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_error(self):
        self.response.code = 400
        self.response.content = json.dumps({
            u'error': {
                u'status': u'INVALID_ARGUMENT',
                u'message': (u'The registration token is not a valid '
                             u'FCM registration token'),
                u'code': 400,
                u'details': [
                    {
                        u'errorCode': u'INVALID_ARGUMENT',
                        u'@type': (u'type.googleapis.com/google.firebase'
                                   u'.fcm.v1.FcmError')},
                    {u'fieldViolations': [
                        {u'field': u'message.token',
                         u'description': (u'The registration token is not '
                                          u'a valid FCM registration token')}],
                        u'@type': u'type.googleapis.com/google.rpc.BadRequest'}
                            ]
            }
        })
        self.router.metrics = Mock()
        self._set_content()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert self.router.metrics.increment.called
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:fcmv1', 'reason:server_error']
            assert "INVALID_ARGUMENT" in str(fail.value)
            self._check_error_call(fail.value, 500)
        d.addBoth(check_results)
        return d

    def test_router_no_token(self):
        uaid_data = dict(
            router_data=dict(
                token=None,
                creds=dict(
                    senderID="fir-bridgetest")))
        with pytest.raises(RouterException):
            self.router.route_notification(self.notif, uaid_data)

    def test_router_timeout(self):
        self.router.metrics = Mock()

        def timeout(*args, **kwargs):
            self._m_request.errback(Failure(TimeoutError()))
            return self._m_request

        self.client._sender.side_effect = timeout
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert self.router.metrics.increment.called
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:fcmv1', 'reason:timeout']

        d.addBoth(check_results)
        return d

    def test_router_unknown_err(self):
        self.router.metrics = Mock()

        def timeout(*args, **kwargs):
            self._m_request.errback(Failure(Exception()))
            return self._m_request

        self.client._sender.side_effect = timeout
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert isinstance(fail.value, RouterException)

        d.addBoth(check_results)
        return d

    def test_fcmv1_amend(self):
        router_data = {"token": "connection_data"}
        self.router.register("uaid", router_data=router_data,
                             app_id="fir-bridgetest")
        resp = {"key": "value"}
        self.router.amend_endpoint_response(
            resp, self.router_data.get('router_data'))
        assert {"key": "value", "senderid": "fir-bridgetest"} == resp

    def test_register_invalid_token(self):
        with pytest.raises(RouterException):
            self.router.register(
                uaid="uaid",
                router_data={"token": "invalid"},
                app_id="invalid")

    def test_bad_credentials(self):
        del(self.fcm_config['creds'])
        with pytest.raises(IOError):
            FCMv1Router(
                AutopushConfig(
                    hostname="localhost",
                    statsd_host=None,
                ),
                self.fcm_config,
                SinkMetrics()
            )

    def test_unknown_appid(self):
        self.router_data["router_data"]["app_id"] = "invalid"
        with pytest.raises(RouterException):
            self.router.route_notification(self.notif, self.router_data)


class FCMRouterTestCase(unittest.TestCase):

    @patch("pyfcm.FCMNotification", spec=pyfcm.FCMNotification)
    def setUp(self, ffcm):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.fcm_config = {'max_data': 32,
                           'ttl': 60,
                           'version': 1,
                           'dryrun': False,
                           'collapsekey': 'simplepush',
                           'creds': {
                               'test123': {
                                   'app_id': 'test123',
                                   'auth': "12345678abcdefg"
                               }}}
        self.router_data = dict(
            router_data=dict(
                token="connect_data",
                app_id="test123"))
        mock_result = dict(
            multicast_id="",
            success=0,
            failure=0,
            canonical_ids=0,
            results=[dict()],
        )
        self.mock_result = mock_result
        self.router = FCMRouter(conf, self.fcm_config, SinkMetrics())
        self.fcm = self.router.clients[
            self.router_data['router_data']['app_id']
        ]
        self.fcm.notify_single_device.return_value = mock_result
        self.headers = {"content-encoding": "aesgcm",
                        "encryption": "test",
                        "encryption-key": "test"}
        # Payloads are Base64-encoded.
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=200
        )
        self.notif.cleanup_headers()

    def _check_error_call(self, exc, code):
        assert isinstance(exc, RouterException)
        assert exc.status_code == code
        assert self.fcm.notify_single_device.called
        self.flushLoggedErrors()

    @patch("pyfcm.FCMNotification", spec=pyfcm.FCMNotification)
    def test_init(self, ffcm):
        def throw_auth(*args, **kwargs):
            raise Exception("oopsy")

        ffcm.side_effect = throw_auth
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        with pytest.raises(IOError):
            FCMRouter(conf, {}, SinkMetrics())

    def test_register(self):
        router_data = {"token": "test123"}
        self.router.register("uaid", router_data=router_data,
                             app_id="test123")
        # Check the information that will be recorded for this user
        assert router_data == {"token": "test123", "app_id": "test123"}

    def test_register_bad(self):
        with pytest.raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="invalid123")

    def test_route_notification(self):
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            assert result.logged_status == 200
            assert "TTL" in result.headers
            assert self.fcm.notify_single_device.called
            # Make sure the data was encoded as base64
            args = self.fcm.notify_single_device.call_args[1]
            data = args['data_message']
            assert data['body'] == 'q60d6g'
            assert data['chid'] == dummy_chid
            assert data['enc'] == 'test'
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
        d.addCallback(check_results)
        return d

    def test_ttl_none(self):
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=None
        )
        self.notif.cleanup_headers()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.fcm.notify_single_device.called
            # Make sure the data was encoded as base64
            args = self.fcm.notify_single_device.call_args[1]
            data = args['data_message']
            assert data['body'] == 'q60d6g'
            assert data['chid'] == dummy_chid
            assert data['enc'] == 'test'
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
            # use the defined min TTL
            assert args['time_to_live'] == 60
        d.addCallback(check_results)
        return d

    def test_ttl_high(self):
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="q60d6g",
            headers=self.headers,
            ttl=5184000
        )
        self.notif.cleanup_headers()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.fcm.notify_single_device.called
            # Make sure the data was encoded as base64
            args = self.fcm.notify_single_device.call_args[1]
            data = args['data_message']
            assert data['body'] == 'q60d6g'
            assert data['chid'] == dummy_chid
            assert data['enc'] == 'test'
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
            # use the defined min TTL
            assert args['time_to_live'] == 2419200
        d.addCallback(check_results)
        return d

    def test_long_data(self):
        bad_notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="\x01abcdefghijklmnopqrstuvwxyz0123456789",
            headers=self.headers,
            ttl=200,
            message_id=10,
        )
        self.notif.cleanup_headers()
        d = self.router.route_notification(bad_notif, self.router_data)

        def check_results(result):
            assert isinstance(result.value, RouterException)
            assert result.value.status_code == 413
            assert result.value.errno == 104

        d.addBoth(check_results)
        return d

    def test_route_crypto_notification(self):
        del(self.notif.headers['encryption_key'])
        self.notif.headers['crypto_key'] = 'crypto'
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.router.clients['test123'].notify_single_device.called
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_auth_error(self):
        def throw_auth(*args, **kwargs):
            raise pyfcm.errors.AuthenticationError()
        self.fcm.notify_single_device.side_effect = throw_auth
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_other_error(self):
        def throw_other(*args, **kwargs):
            raise Exception("oh my!")
        self.fcm.notify_single_device.side_effect = throw_other
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500)
        d.addBoth(check_results)
        return d

    def test_router_notification_connection_error(self):
        from requests.exceptions import ConnectionError

        def throw_other(*args, **kwargs):
            raise ConnectionError("oh my!")

        self.fcm.notify_single_device.side_effect = throw_other
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 502)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_id_change(self):
        self.mock_result['canonical_ids'] = 1
        self.mock_result['results'][0] = {'registration_id': "new"}
        self.fcm.notify_single_device.return_value = self.mock_result
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict(token="new")
            assert self.fcm.notify_single_device.called
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_not_regged(self):
        self.mock_result['failure'] = 1
        self.mock_result['results'][0] = {'error': 'NotRegistered'}
        self.fcm.notify_single_device.return_value = self.mock_result
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict()
            assert self.fcm.notify_single_device.called
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_failed_items(self):
        self.mock_result['failure'] = 1
        self.mock_result['results'][0] = {'error':
                                          'TopicsMessageRateExceeded'}
        self.fcm.notify_single_device.return_value = self.mock_result
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 503)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_no_auth(self):
        d = self.router.route_notification(self.notif,
                                           {"router_data": {"token": ""}})

        def check_results(fail):
            assert fail.value.status_code == 410
        d.addBoth(check_results)
        return d

    def test_fcm_amend(self):
        self.router.register(uaid="uaid",
                             router_data={"token": "test123"},
                             app_id="test123")
        resp = {"key": "value"}
        self.router.amend_endpoint_response(
            resp, self.router_data.get('router_data'))
        assert {"key": "value", "senderid": "test123"} == resp

    def test_register_invalid_token(self):
        with pytest.raises(RouterException):
            self.router.register(
                uaid="uaid",
                router_data={"token": "invalid"},
                app_id="invalid")


class WebPushRouterTestCase(unittest.TestCase):
    def setUp(self):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.metrics = metrics = Mock(spec=SinkMetrics)
        self.db = db = test_db(metrics=metrics)

        self.headers = headers = {
            "content-encoding": "aes128",
            "encryption": "awesomecrypto",
            "crypto-key": "niftykey"
        }
        self.agent_mock = agent = Mock(spec=Agent)
        self.router = WebPushRouter(conf, {}, db, agent)
        self.notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="data",
            headers=headers,
            ttl=20,
            message_id=uuid.uuid4().hex,
        )
        self.notif.cleanup_headers()
        mock_result = Mock(spec=gcmclient.Result)
        mock_result.canonical = dict()
        mock_result.failed = dict()
        mock_result.not_registered = dict()
        mock_result.retry_after = 1000
        self.router_mock = db.router
        self.message_mock = db._message = Mock(spec=Message)
        self.conf = conf

    def test_route_to_busy_node_saves_looks_up_and_sends_check_201(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.addCallback.return_value = response_mock
        type(response_mock).code = PropertyMock(
            side_effect=MockAssist([202, 200]))
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = (True, [dummy_chid])
        self.db.message_table = Mock(return_value=self.message_mock)
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        self.router_mock.get_uaid.return_value = router_data
        self.router.message_id = uuid.uuid4().hex

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            kwargs = self.message_mock.store_message.call_args[1]
            t_h = kwargs["notification"].headers
            assert t_h.get('encryption') == self.headers.get('encryption')
            assert t_h.get('crypto_key') == self.headers.get('crypto-key')
            assert t_h.get('encoding') == self.headers.get('content-encoding')
            assert "Location" in result.headers

        d.addCallback(verify_deliver)
        return d

    def test_route_failure(self):
        self.agent_mock.request = Mock(side_effect=ConnectionRefusedError)
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = (True, [dummy_chid])
        self.db.message_table = Mock(return_value=self.message_mock)
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        self.router_mock.get_uaid.return_value = router_data
        self.router.message_id = uuid.uuid4().hex

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            kwargs = self.message_mock.store_message.call_args[1]
            assert len(self.metrics.increment.mock_calls) == 3
            t_h = kwargs["notification"].headers
            assert t_h.get('encryption') == self.headers.get('encryption')
            assert t_h.get('crypto_key') == self.headers.get('crypto-key')
            assert t_h.get('encoding') == self.headers.get('content-encoding')
            assert "Location" in result.headers

        d.addCallback(verify_deliver)
        return d

    def test_route_to_busy_node_with_ttl_zero(self):
        notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="data",
            headers=self.headers,
            ttl=0,
            message_id=uuid.uuid4().hex,
        )
        self.notif.cleanup_headers()
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.addCallback.return_value = response_mock
        type(response_mock).code = PropertyMock(
            side_effect=MockAssist([202, 200]))
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = (True, [dummy_chid])
        self.db.message_table = Mock(return_value=self.message_mock)
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        self.router_mock.get_uaid.return_value = router_data
        self.router.message_id = uuid.uuid4().hex

        d = self.router.route_notification(notif, router_data)

        def verify_deliver(fail):
            exc = fail.value
            assert isinstance(exc, RouterException)
            assert exc.status_code == 201
            assert len(self.metrics.increment.mock_calls) == 0
            assert "Location" in exc.headers
        d.addBoth(verify_deliver)
        return d

    def test_amend(self):
        resp = {"key": "value"}
        expected = resp.copy()
        self.router.amend_endpoint_response(resp, {})
        assert resp == expected

    def test_route_to_busy_node_save_throws_db_error(self):

        def throw():
            raise ClientError(
                {'Error': {'Code': 'InternalServerError'}},
                'mock_store_message'
            )

        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.code = 202
        self.message_mock.store_message.side_effect = MockAssist([throw])
        self.db.message_table = Mock(return_value=self.message_mock)
        router_data = dict(node_id="http://somewhere",
                           uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(fail):
            exc = fail.value
            assert isinstance(exc, RouterException)
            assert exc.status_code == 503
        d.addBoth(verify_deliver)

        return d

    def test_route_lookup_uaid_fails(self):

        def throw():
            raise ClientError(
                {'Error': {'Code': 'InternalServerError'}},
                'mock_get_uaid'
            )

        self.message_mock.store_message.return_value = True
        self.db.message_table = Mock(return_value=self.message_mock)
        self.router_mock.get_uaid.side_effect = MockAssist(
            [throw]
        )
        router_data = dict(node_id="http://somewhere",
                           uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(status):
            assert status.status_code == 201
        d.addBoth(verify_deliver)

        return d

    def test_route_lookup_uaid_not_found(self):

        def throw():
            raise ItemNotFound()

        self.message_mock.store_message.return_value = True
        self.db.message_table = Mock(return_value=self.message_mock)
        self.router_mock.get_uaid.side_effect = MockAssist(
            [throw]
        )
        router_data = dict(node_id="http://somewhere",
                           uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(status):
            assert status.value.status_code == 410
        d.addBoth(verify_deliver)

        return d

    def test_route_lookup_uaid_no_nodeid(self):
        self.message_mock.store_message.return_value = True
        self.db.message_table = Mock(return_value=self.message_mock)
        self.router_mock.get_uaid.return_value = dict()
        router_data = dict(node_id="http://somewhere",
                           uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(status):
            assert status.status_code == 201
        d.addBoth(verify_deliver)

        return d

    def test_route_and_clear_failure(self):
        self.agent_mock.request = Mock(side_effect=ConnectionRefusedError)
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = (True, [dummy_chid])
        self.db.message_table = Mock(return_value=self.message_mock)
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        self.router_mock.get_uaid.return_value = router_data

        def throw():
            raise ClientError(
                {'Error': {'Code': 'InternalServerError'}},
                'mock_clear_node'
            )

        self.router_mock.clear_node.side_effect = MockAssist([throw])
        self.router.message_id = uuid.uuid4().hex

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            kwargs = self.message_mock.store_message.call_args[1]
            assert len(self.metrics.increment.mock_calls) == 3
            t_h = kwargs["notification"].headers
            assert t_h.get('encryption') == self.headers.get('encryption')
            assert t_h.get('crypto_key') == self.headers.get('crypto-key')
            assert t_h.get('encoding') == self.headers.get('content-encoding')
            assert "Location" in result.headers

        d.addCallback(verify_deliver)
        return d
