# -*- coding: utf-8 -*-
from unittest import TestCase
import uuid
import time
import json
import decimal

from autopush.utils import WebPushNotification
from mock import Mock, PropertyMock, patch
from nose.tools import eq_, ok_, assert_raises
from twisted.trial import unittest
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.defer import inlineCallbacks
from twisted.web.client import Agent

import hyper
import hyper.tls
import gcmclient
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
)
from autopush.router.interface import RouterResponse, IRouter
from autopush.tests import MockAssist
from autopush.tests.support import test_db


class RouterInterfaceTestCase(TestCase):
    def test_not_implemented(self):
        assert_raises(NotImplementedError, IRouter, None, None)

        def init(self, conf, router_conf):
            pass
        IRouter.__init__ = init
        ir = IRouter(None, None)
        assert_raises(NotImplementedError, ir.register, "uaid", {}, "")
        assert_raises(NotImplementedError, ir.route_notification, "uaid", {})
        assert_raises(NotImplementedError, ir.amend_endpoint_response, {}, {})


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
        self.router.register("uaid", router_data=router_data, app_id="firefox")
        eq_(router_data, {"rel_channel": "firefox", "token": "connect_data"})

    def test_extended_register(self):
        router_data = {"token": "connect_data",
                       "aps": {"foo": "bar",
                               "gorp": "baz"}}
        self.router.register("uaid", router_data=router_data, app_id="firefox")
        eq_(router_data, {"rel_channel": "firefox", "token": "connect_data",
                          "aps": {"foo": "bar", "gorp": "baz"}})

    def test_register_bad(self):
        with assert_raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="firefox")

    def test_register_bad_channel(self):
        with assert_raises(RouterException):
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

        with assert_raises(RouterException) as e:
            yield self.router.route_notification(self.notif, self.router_data)

        eq_(e.exception.response_body, 'APNS returned an error '
                                       'processing request')
        eq_(e.exception.status_code, 502)
        self.flushLoggedErrors()

    @inlineCallbacks
    def test_route_notification(self):
        result = yield self.router.route_notification(self.notif,
                                                      self.router_data)
        yield self._waitfor(lambda:
                            self.mock_connection.request.called is True)

        ok_(isinstance(result, RouterResponse))
        ok_(self.mock_connection.request.called)
        body = self.mock_connection.request.call_args[1]
        body_json = json.loads(body['body'])
        ok_('chid' in body_json)
        # The ChannelID is a UUID4, and unpredictable.
        del(body_json['chid'])
        eq_(body_json, {
            "body": "q60d6g",
            "enc": "test",
            "ver": 10,
            "aps": {
                "mutable-content": 1,
                "alert": {"title": " ", "body": " "}
            },
            "enckey": "test",
            "con": "aesgcm",
        })

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
        ok_(isinstance(result, RouterResponse))
        ok_(self.mock_connection.request.called)
        body = self.mock_connection.request.call_args[1]
        body_json = json.loads(body['body'])
        eq_(body_json['aps']['number'], 4)
        eq_(body_json['aps']['string'], 'String')

    @inlineCallbacks
    def test_route_low_priority_notification(self):
        """low priority and empty apns_ids are not yet used, but may feature
        when priorty work is done."""
        apns2 = self.router.apns['firefox']
        exp = int(time.time()+300)
        yield apns2.send("abcd0123", {}, 'apnsid', priority=False, exp=exp)
        yield self._waitfor(lambda:
                            self.mock_connection.request.called is True)
        ok_(self.mock_connection.request.called)
        body = self.mock_connection.request.call_args[1]
        headers = body['headers']
        eq_(headers, {'apns-expiration': str(exp),
                      'apns-topic': 'com.example.SomeApp',
                      'apns-priority': '5',
                      'apns-id': 'apnsid'})

    @inlineCallbacks
    def test_bad_send(self):
        self.mock_response.status = 400
        self.mock_response.read.return_value = json.dumps({'reason': 'boo'})
        with assert_raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)
        ok_(isinstance(ex.exception, RouterException))
        eq_(ex.exception.status_code, 502)
        eq_(ex.exception.message, 'APNS Transmit Error 400:boo')
        eq_(ex.exception.response_body, 'APNS could not process your '
                                        'message boo')

    @inlineCallbacks
    def test_fail_send(self):
        def throw(*args, **kwargs):
            raise HTTP20Error("oops")

        self.router.apns['firefox'].connections[0].request.side_effect = throw
        with assert_raises(RouterException) as ex:
            yield self.router.route_notification(self.notif, self.router_data)
        ok_(isinstance(ex.exception, RouterException))
        eq_(ex.exception.status_code, 502)
        eq_(ex.exception.message, "Server error")
        eq_(ex.exception.response_body, 'APNS returned an error processing '
                                        'request')
        self.flushLoggedErrors()

    def test_too_many_connections(self):
        rr = self.router.apns['firefox']
        with assert_raises(RouterException) as ex:
            while True:
                rr._get_connection()

        ok_(isinstance(ex.exception, RouterException))
        eq_(ex.exception.status_code, 503)
        eq_(ex.exception.message, "Too many APNS requests, "
                                  "increase pool from 2")
        eq_(ex.exception.response_body, "APNS busy, please retry")

    def test_amend(self):
        resp = {"key": "value"}
        expected = resp.copy()
        self.router.amend_endpoint_response(resp, {})
        eq_(resp, expected)

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
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 201)
            eq_(result.logged_status, 200)
            ok_("TTL" in result.headers)
            ok_(self.mock_connection.called)

        d.addCallback(check_results)
        return d


class GCMRouterTestCase(unittest.TestCase):

    @patch("gcmclient.gcm.GCM", spec=gcmclient.gcm.GCM)
    def setUp(self, fgcm):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        self.gcm_config = {'max_data': 32,
                           'ttl': 60,
                           'senderIDs': {'test123':
                                         {"auth": "12345678abcdefg"}}}
        self.gcm = fgcm
        self.router = GCMRouter(conf, self.gcm_config, SinkMetrics())
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
        mock_result = Mock(spec=gcmclient.gcm.Result)
        mock_result.canonical = dict()
        mock_result.failed = dict()
        mock_result.not_registered = dict()
        mock_result.needs_retry.return_value = False
        self.mock_result = mock_result
        fgcm.send.return_value = mock_result

    def _check_error_call(self, exc, code, response=None):
        ok_(isinstance(exc, RouterException))
        eq_(exc.status_code, code)
        ok_(self.router.gcm['test123'].send.called)
        if response:
            eq_(exc.response_body, response)
        self.flushLoggedErrors()

    def test_init(self):
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        with assert_raises(IOError):
            GCMRouter(conf, {"senderIDs": {}}, SinkMetrics())

    def test_register(self):
        router_data = {"token": "test123"}
        self.router.register("uaid", router_data=router_data, app_id="test123")
        # Check the information that will be recorded for this user
        eq_(router_data, {"token": "test123",
                          "creds": {"senderID": "test123",
                                    "auth": "12345678abcdefg"}})

    def test_register_bad(self):
        with assert_raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="")
        with assert_raises(RouterException):
            self.router.register("uaid", router_data={}, app_id='')
        with assert_raises(RouterException):
            self.router.register(
                "uaid",
                router_data={"token": "abcd1234"},
                app_id="invalid123")

    @patch("gcmclient.GCM")
    def test_gcmclient_fail(self, fgcm):
        fgcm.side_effect = Exception
        conf = AutopushConfig(
            hostname="localhost",
            statsd_host=None,
        )
        with assert_raises(IOError):
            GCMRouter(
                conf,
                {"senderIDs": {"test123": {"auth": "abcd"}}},
                SinkMetrics()
            )

    def test_route_notification(self):
        self.router.gcm['test123'] = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            ok_(self.router.gcm['test123'].send.called)
            # Make sure the data was encoded as base64
            data = self.router.gcm['test123'].send.call_args[0][0].data
            eq_(data['body'], 'q60d6g')
            eq_(data['enc'], 'test')
            eq_(data['chid'], dummy_chid)
            eq_(data['enckey'], 'test')
            eq_(data['con'], 'aesgcm')
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
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 201)
            eq_(result.logged_status, 200)
            ok_("TTL" in result.headers)
            ok_(self.router.gcm['test123'].send.called)
            # Make sure the data was encoded as base64
            data = self.router.gcm['test123'].send.call_args[0][0].data
            options = self.router.gcm['test123'].send.call_args[0][0].options
            eq_(data['body'], 'q60d6g')
            eq_(data['enc'], 'test')
            eq_(data['chid'], dummy_chid)
            eq_(data['enckey'], 'test')
            eq_(data['con'], 'aesgcm')
            # use the defined min TTL
            eq_(options['time_to_live'], 60)
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
            ok_(isinstance(result, RouterResponse))
            ok_(self.router.gcm['test123'].send.called)
            # Make sure the data was encoded as base64
            data = self.router.gcm['test123'].send.call_args[0][0].data
            options = self.router.gcm['test123'].send.call_args[0][0].options
            eq_(data['body'], 'q60d6g')
            eq_(data['enc'], 'test')
            eq_(data['chid'], dummy_chid)
            eq_(data['enckey'], 'test')
            eq_(data['con'], 'aesgcm')
            # use the defined min TTL
            eq_(options['time_to_live'], 2419200)
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
            ok_(isinstance(result.value, RouterException))
            eq_(result.value.status_code, 413)
            eq_(result.value.errno, 104)

        d.addBoth(check_results)
        return d

    def test_route_crypto_notification(self):
        self.router.gcm['test123'] = self.gcm
        del(self.notif.headers['encryption_key'])
        self.notif.headers['crypto_key'] = 'crypto'
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            ok_(self.router.gcm['test123'].send.called)
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_auth_error(self):
        def throw_auth(arg):
            raise gcmclient.GCMAuthenticationError()
        self.gcm.send.side_effect = throw_auth
        self.router.gcm['test123'] = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error")
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_other_error(self):
        def throw_other(arg):
            raise Exception("oh my!")
        self.gcm.send.side_effect = throw_other
        self.router.gcm['test123'] = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500, "Server error")
        d.addBoth(check_results)
        return d

    def test_router_notification_connection_error(self):
        from requests.exceptions import ConnectionError

        def throw_other(*args, **kwargs):
            raise ConnectionError("oh my!")

        self.gcm.send.side_effect = throw_other
        self.router.gcm['test123'] = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 502, "Server error")
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_id_change(self):
        self.mock_result.canonical["old"] = "new"
        self.router.gcm['test123'] = self.gcm
        self.router.metrics = Mock()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict(token="new"))
            eq_(self.router.metrics.increment.call_args[0][0],
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            eq_(self.router.metrics.increment.call_args[1]['tags'],
                ['platform:gcm', 'reason:reregister'])
            ok_(self.router.gcm['test123'].send.called)
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_not_regged(self):
        self.mock_result.not_registered = {"connect_data": True}
        self.router.gcm['test123'] = self.gcm
        self.router.metrics = Mock()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict())
            eq_(self.router.metrics.increment.call_args[0][0],
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            eq_(self.router.metrics.increment.call_args[1]['tags'],
                ['platform:gcm', 'reason:unregistered'])
            ok_(self.router.gcm['test123'].send.called)
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_failed_items(self):
        self.mock_result.failed = dict(connect_data=True)
        self.router.gcm['test123'] = self.gcm
        self.router.metrics = Mock()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            ok_(self.router.metrics.increment.called)
            eq_(self.router.metrics.increment.call_args[0][0],
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            eq_(self.router.metrics.increment.call_args[1]['tags'],
                ['platform:gcm', 'reason:failure'])
            eq_(fail.value.message, 'GCM unable to deliver')
            self._check_error_call(fail.value, 410)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_needs_retry(self):
        self.mock_result.needs_retry.return_value = True
        self.router.gcm['test123'] = self.gcm
        self.router.metrics = Mock()
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            ok_(self.router.metrics.increment.called)
            eq_(self.router.metrics.increment.call_args[0][0],
                'notification.bridge.error')
            self.router.metrics.increment.call_args[1]['tags'].sort()
            eq_(self.router.metrics.increment.call_args[1]['tags'],
                ['platform:gcm', 'reason:retry'])
            eq_(fail.value.message, 'GCM failure to deliver, retry')
            self._check_error_call(fail.value, 503)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_no_auth(self):
        d = self.router.route_notification(self.notif,
                                           {"router_data": {"token": "abc"}})

        def check_results(fail):
            eq_(fail.value.status_code, 500, "Server error")
        d.addBoth(check_results)
        return d

    def test_amend(self):
        router_data = {"token": "test123"}
        self.router.register("uaid", router_data=router_data, app_id="test123")
        resp = {"key": "value"}
        self.router.amend_endpoint_response(
            resp, self.router_data.get('router_data'))
        eq_({"key": "value", "senderid": "test123"}, resp)

    def test_register_invalid_token(self):
        with assert_raises(RouterException):
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
        ok_(isinstance(exc, RouterException))
        eq_(exc.status_code, code)
        ok_(self.router.fcm.notify_single_device.called)
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
        with assert_raises(IOError):
            FCMRouter(conf, {}, SinkMetrics())

    def test_register(self):
        router_data = {"token": "test123"}
        self.router.register("uaid", router_data=router_data, app_id="test123")
        # Check the information that will be recorded for this user
        eq_(router_data, {"token": "test123",
                          "creds": {"senderID": "test123",
                                    "auth": "12345678abcdefg"}})

    def test_register_bad(self):
        with assert_raises(RouterException):
            self.router.register("uaid", router_data={}, app_id="invalid123")

    def test_route_notification(self):
        self.router.fcm = self.fcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 201)
            eq_(result.logged_status, 200)
            ok_("TTL" in result.headers)
            ok_(self.router.fcm.notify_single_device.called)
            # Make sure the data was encoded as base64
            args = self.router.fcm.notify_single_device.call_args[1]
            data = args['data_message']
            eq_(data['body'], 'q60d6g')
            eq_(data['chid'], dummy_chid)
            eq_(data['enc'], 'test')
            eq_(data['enckey'], 'test')
            eq_(data['con'], 'aesgcm')
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
            ok_(isinstance(result, RouterResponse))
            ok_(self.router.fcm.notify_single_device.called)
            # Make sure the data was encoded as base64
            args = self.router.fcm.notify_single_device.call_args[1]
            data = args['data_message']
            eq_(data['body'], 'q60d6g')
            eq_(data['chid'], dummy_chid)
            eq_(data['enc'], 'test')
            eq_(data['enckey'], 'test')
            eq_(data['con'], 'aesgcm')
            # use the defined min TTL
            eq_(args['time_to_live'], 60)
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
            ok_(isinstance(result, RouterResponse))
            ok_(self.router.fcm.notify_single_device.called)
            # Make sure the data was encoded as base64
            args = self.router.fcm.notify_single_device.call_args[1]
            data = args['data_message']
            eq_(data['body'], 'q60d6g')
            eq_(data['chid'], dummy_chid)
            eq_(data['enc'], 'test')
            eq_(data['enckey'], 'test')
            eq_(data['con'], 'aesgcm')
            # use the defined min TTL
            eq_(args['time_to_live'], 2419200)
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
            ok_(isinstance(result.value, RouterException))
            eq_(result.value.status_code, 413)
            eq_(result.value.errno, 104)

        d.addBoth(check_results)
        return d

    def test_route_crypto_notification(self):
        self.router.fcm = self.fcm
        del(self.notif.headers['encryption_key'])
        self.notif.headers['crypto_key'] = 'crypto'
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            ok_(self.router.fcm.notify_single_device.called)
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
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict(token="new"))
            ok_(self.router.fcm.notify_single_device.called)
        d.addCallback(check_results)
        return d

    def test_router_notification_fcm_not_regged(self):
        self.mock_result['failure'] = 1
        self.mock_result['results'][0] = {'error': 'NotRegistered'}
        self.router.fcm = self.fcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict())
            ok_(self.router.fcm.notify_single_device.called)
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
            eq_(fail.value.status_code, 410)
        d.addBoth(check_results)
        return d

    def test_amend(self):
        self.router.register(uaid="uaid",
                             router_data={"token": "test123"},
                             app_id="test123")
        resp = {"key": "value"}
        self.router.amend_endpoint_response(
            resp, self.router_data.get('router_data'))
        eq_({"key": "value", "senderid": "test123"}, resp)

    def test_register_invalid_token(self):
        with assert_raises(RouterException):
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
        mock_result = Mock(spec=gcmclient.gcm.Result)
        mock_result.canonical = dict()
        mock_result.failed = dict()
        mock_result.not_registered = dict()
        mock_result.needs_retry.return_value = False
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
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 201)
            kwargs = self.message_mock.store_message.call_args[1]
            t_h = kwargs["notification"].headers
            eq_(t_h.get('encryption'), self.headers.get('encryption'))
            eq_(t_h.get('crypto_key'), self.headers.get('crypto-key'))
            eq_(t_h.get('encoding'), self.headers.get('content-encoding'))
            ok_("Location" in result.headers)

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
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 201)
            kwargs = self.message_mock.store_message.call_args[1]
            eq_(len(self.metrics.increment.mock_calls), 3)
            t_h = kwargs["notification"].headers
            eq_(t_h.get('encryption'), self.headers.get('encryption'))
            eq_(t_h.get('crypto_key'), self.headers.get('crypto-key'))
            eq_(t_h.get('encoding'), self.headers.get('content-encoding'))
            ok_("Location" in result.headers)

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
            ok_(exc, RouterResponse)
            eq_(exc.status_code, 201)
            eq_(len(self.metrics.increment.mock_calls), 0)
            ok_("Location" in exc.headers)
        d.addBoth(verify_deliver)
        return d

    def test_amend(self):
        resp = {"key": "value"}
        expected = resp.copy()
        self.router.amend_endpoint_response(resp, {})
        eq_(resp, expected)

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
            ok_(exc, RouterException)
            eq_(exc.status_code, 503)
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
            ok_(status.status_code, 201)
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
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 201)
            kwargs = self.message_mock.store_message.call_args[1]
            eq_(len(self.metrics.increment.mock_calls), 3)
            t_h = kwargs["notification"].headers
            eq_(t_h.get('encryption'), self.headers.get('encryption'))
            eq_(t_h.get('crypto_key'), self.headers.get('crypto-key'))
            eq_(t_h.get('encoding'), self.headers.get('content-encoding'))
            ok_("Location" in result.headers)

        d.addCallback(verify_deliver)
        return d
