# -*- coding: utf-8 -*-
from unittest import TestCase
import uuid
import time
import json
import decimal
import requests

from autopush.utils import WebPushNotification
from mock import Mock, PropertyMock, patch
import pytest
from twisted.trial import unittest
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.defer import inlineCallbacks
from twisted.web.client import Agent

import hyper
import hyper.tls
import pyfcm
from hyper.http20.exceptions import HTTP20Error

from autopush.config import AutopushConfig
from autopush.db import (
    Message
)
from autopush.exceptions import RouterException
from autopush.metrics import SinkMetrics
from autopush.router import (
    APNSRouter,
    GCMRouter,
    WebPushRouter,
    FCMRouter,
    gcmclient)
from autopush.router.interface import RouterResponse, IRouter
from autopush.tests import MockAssist
from autopush.tests.support import test_db


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
        self.router = APNSRouter(conf, apns_config, SinkMetrics())
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
        assert ex.value.message == 'APNS Transmit Error 400:boo'
        assert ex.value.response_body == (
            'APNS could not process your message boo')

    @inlineCallbacks
    def test_fail_send(self):
        def throw(*args, **kwargs):
            raise HTTP20Error("oops")

        self.router.apns['firefox'].connections[0].request.side_effect = throw
        with pytest.raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)
        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 502
        assert ex.value.message == "Server error"
        assert ex.value.response_body == 'APNS returned an error ' \
                                         'processing request'
        self.flushLoggedErrors()

    def test_too_many_connections(self):
        rr = self.router.apns['firefox']
        with pytest.raises(RouterException) as ex:
            while True:
                rr._get_connection()

        assert isinstance(ex.value, RouterException)
        assert ex.value.status_code == 503
        assert ex.value.message == "Too many APNS requests, " \
                                   "increase pool from 2"
        assert ex.value.response_body == "APNS busy, please retry"

    def test_amend(self):
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
                                         {"auth": "12345678abcdefg"}}}
        self.response = Mock(spec=requests.Response)
        self.response.status_code = 200
        self.response.headers = dict()
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
        self.gcm = gcmclient.GCM(api_key="SomeKey")
        self.gcm._sender = Mock(return_value=self.response)
        self.router = GCMRouter(conf, self.gcm_config, SinkMetrics())
        self.router.gcm['test123'] = self.gcm
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

    def _check_error_call(self, exc, code, response=None, errno=None):
        assert isinstance(exc, RouterException)
        assert exc.status_code == code
        if errno is not None:
            assert exc.errno == errno
        assert self.gcm._sender.called
        if response:
            assert exc.response_body == response
        self.flushLoggedErrors()

    def test_init(self):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        with pytest.raises(IOError):
            GCMRouter(conf, {"senderIDs": {}}, SinkMetrics())

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
        self.router.gcm['test123'] = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.gcm._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.gcm._sender.call_args[1]['data'])
            data = payload['data']
            assert data['body'] == 'q60d6g'
            assert data['enc'] == 'test'
            assert data['chid'] == dummy_chid
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
        d.addCallback(check_results)
        return d

    def test_ttl_none(self):
        self.router.gcm['test123'] = self.gcm
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
            assert result.status_code == 201
            assert result.logged_status == 200
            assert "TTL" in result.headers
            assert self.gcm._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.gcm._sender.call_args[1]['data'])
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
        self.router.gcm['test123'] = self.gcm
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
            assert self.gcm._sender.called
            # Make sure the data was encoded as base64
            payload = json.loads(self.gcm._sender.call_args[1]['data'])
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
        self.router.gcm['test123'] = self.gcm
        bad_notif = WebPushNotification(
            uaid=uuid.UUID(dummy_uaid),
            channel_id=uuid.UUID(dummy_chid),
            data="\x01abcdefghijklmnopqrstuvwxyz0123456789",
            headers=self.headers,
            ttl=200
        )

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
            assert self.gcm._sender.called
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_auth_error(self):
        self.response.status_code = 401
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error", 901)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_other_error(self):
        self.gcm._sender.side_effect = Exception
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error")
        d.addBoth(check_results)
        return d

    def test_router_notification_connection_error(self):
        from requests.exceptions import ConnectionError

        def throw_other(*args, **kwargs):
            raise ConnectionError("oh my!")

        self.gcm._sender.side_effect = throw_other
        self.router.gcm['test123'] = self.gcm
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
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict(token="new")
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:reregister']
            assert self.gcm._sender.called
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
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict()
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:unregistered']
            assert self.gcm._sender.called
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
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert self.router.metrics.increment.called
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:failure']
            assert fail.value.message == 'GCM unable to deliver'
            self._check_error_call(fail.value, 410)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_needs_retry(self):
        self.response.headers['Retry-After'] = "123"
        self.response.status_code = 500
        self.response.content = ""
        self.router.metrics = Mock()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            assert self.router.metrics.increment.called
            assert self.router.metrics.increment.call_args[0][0] == (
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            assert self.router.metrics.increment.call_args[1]['tags'] == [
                'platform:gcm', 'reason:retry']
            assert fail.value.message == 'GCM failure to deliver, retry'
            self._check_error_call(fail.value, 503)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_no_auth(self):
        d = self.router.route_notification(self.notif,
                                           {"router_data": {"token": "abc"}})

        def check_results(fail):
            assert isinstance(fail.value, RouterException)
            assert fail.value.message == "Server error"
            assert fail.value.status_code == 500
            assert fail.value.errno == 900
        d.addBoth(check_results)
        return d

    def test_amend(self):
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


class FCMRouterTestCase(unittest.TestCase):

    @patch("pyfcm.FCMNotification", spec=pyfcm.FCMNotification)
    def setUp(self, ffcm):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.fcm_config = {'max_data': 32,
                           'ttl': 60,
                           'senderID': 'test123',
                           "auth": "12345678abcdefg"}
        self.fcm = ffcm
        self.router = FCMRouter(conf, self.fcm_config, SinkMetrics())
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
        self.router_data = dict(
            router_data=dict(
                token="connect_data",
                creds=dict(senderID="test123", auth="12345678abcdefg")))
        mock_result = dict(
            multicast_id="",
            success=0,
            failure=0,
            canonical_ids=0,
            results=[dict()],
        )
        self.mock_result = mock_result
        ffcm.notify_single_device.return_value = mock_result

    def _check_error_call(self, exc, code):
        assert isinstance(exc, RouterException)
        assert exc.status_code == code
        assert self.router.fcm.notify_single_device.called
        self.flushLoggedErrors()

    @patch("pyfcm.FCMNotification", spec=pyfcm.FCMNotification)
    def test_init(self, ffcm):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )

        def throw_auth(*args, **kwargs):
            raise Exception("oopsy")

        ffcm.side_effect = throw_auth
        with pytest.raises(IOError):
            FCMRouter(conf, {}, SinkMetrics())

    def test_register(self):
        router_data = {"token": "test123"}
        self.router.register("uaid", router_data=router_data,
                             app_id="test123")
        # Check the information that will be recorded for this user
        assert router_data == {
            "token": "test123",
            "creds": {"senderID": "test123",
                      "auth": "12345678abcdefg"}}

    def test_register_bad(self):
        with pytest.raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="invalid123")

    def test_route_notification(self):
        self.router.fcm = self.fcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.status_code == 201
            assert result.logged_status == 200
            assert "TTL" in result.headers
            assert self.router.fcm.notify_single_device.called
            # Make sure the data was encoded as base64
            args = self.router.fcm.notify_single_device.call_args[1]
            data = args['data_message']
            assert data['body'] == 'q60d6g'
            assert data['chid'] == dummy_chid
            assert data['enc'] == 'test'
            assert data['enckey'] == 'test'
            assert data['con'] == 'aesgcm'
        d.addCallback(check_results)
        return d

    def test_ttl_none(self):
        self.router.fcm = self.fcm
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
            assert self.router.fcm.notify_single_device.called
            # Make sure the data was encoded as base64
            args = self.router.fcm.notify_single_device.call_args[1]
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
        self.router.fcm = self.fcm
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
            assert self.router.fcm.notify_single_device.called
            # Make sure the data was encoded as base64
            args = self.router.fcm.notify_single_device.call_args[1]
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
        self.router.fcm = self.fcm
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
        self.router.fcm = self.fcm
        del(self.notif.headers['encryption_key'])
        self.notif.headers['crypto_key'] = 'crypto'
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert self.router.fcm.notify_single_device.called
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_auth_error(self):
        def throw_auth(*args, **kwargs):
            raise pyfcm.errors.AuthenticationError()
        self.fcm.notify_single_device.side_effect = throw_auth
        self.router.fcm = self.fcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_other_error(self):
        def throw_other(*args, **kwargs):
            raise Exception("oh my!")
        self.fcm.notify_single_device.side_effect = throw_other
        self.router.fcm = self.fcm
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
        self.router.fcm = self.fcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 502)
        d.addBoth(check_results)
        return d

    def test_router_notification_fcm_id_change(self):
        self.mock_result['canonical_ids'] = 1
        self.mock_result['results'][0] = {'registration_id': "new"}
        self.router.fcm = self.fcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict(token="new")
            assert self.router.fcm.notify_single_device.called
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_not_regged(self):
        self.mock_result['failure'] = 1
        self.mock_result['results'][0] = {'error': 'NotRegistered'}
        self.router.fcm = self.fcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            assert isinstance(result, RouterResponse)
            assert result.router_data == dict()
            assert self.router.fcm.notify_single_device.called
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_failed_items(self):
        self.mock_result['failure'] = 1
        self.mock_result['results'][0] = {'error':
                                          'TopicsMessageRateExceeded'}
        self.router.fcm = self.fcm
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

    def test_amend(self):
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
        self.message_mock = db.message = Mock(spec=Message)
        self.conf = conf

    def test_route_to_busy_node_saves_looks_up_and_sends_check_201(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.addCallback.return_value = response_mock
        type(response_mock).code = PropertyMock(
            side_effect=MockAssist([202, 200]))
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = (True, [dummy_chid])
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
        from boto.dynamodb2.exceptions import JSONResponseError

        def throw():
            raise JSONResponseError(500, "Whoops")

        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.code = 202
        self.message_mock.store_message.side_effect = MockAssist(
            [throw]
        )
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
        from boto.dynamodb2.exceptions import JSONResponseError

        def throw():
            raise JSONResponseError(500, "Whoops")

        self.message_mock.store_message.return_value = True
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
        from boto.dynamodb2.exceptions import ItemNotFound

        def throw():
            raise ItemNotFound()

        self.message_mock.store_message.return_value = True
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
        self.router_mock.get_uaid.return_value = dict(

        )
        router_data = dict(node_id="http://somewhere",
                           uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(status):
            assert status.status_code == 201
        d.addBoth(verify_deliver)

        return d

    def test_route_and_clear_failure(self):
        from boto.dynamodb2.exceptions import JSONResponseError
        self.agent_mock.request = Mock(side_effect=ConnectionRefusedError)
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = (True, [dummy_chid])
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid,
                           current_month=self.db.current_msg_month)
        self.router_mock.get_uaid.return_value = router_data

        def throw():
            raise JSONResponseError(500, "Whoops")

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
