# -*- coding: utf-8 -*-
from unittest import TestCase
import uuid

from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.trial import unittest

import apns
import gcmclient

from autopush.endpoint import Notification
from autopush.router import APNSRouter, GCMRouter
from autopush.router.interface import RouterException, RouterResponse, IRouter
from autopush.settings import AutopushSettings


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class RouterTestCase(TestCase):
    pass


class RouterInterfaceTestCase(TestCase):
    def test_not_implemented(self):
        self.assertRaises(NotImplementedError, IRouter, None, None)

        def init(self, settings, router_conf):
            pass
        IRouter.__init__ = init
        ir = IRouter(None, None)
        self.assertRaises(NotImplementedError, ir.register, "uaid", {})
        self.assertRaises(NotImplementedError, ir.route_notification, "uaid",
                          {})


dummy_chid = str(uuid.uuid4())


class APNSRouterTestCase(unittest.TestCase):
    def setUp(self):
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        apns_config = {'cert_file': 'fake.cert', 'key_file': 'fake.key'}
        self.mock_apns = Mock(spec=apns.APNs)
        self.router = APNSRouter(settings, apns_config)
        self.router.apns = self.mock_apns
        self.notif = Notification(10, "data", dummy_chid)
        self.router_data = dict(token="connect_data")

    def test_register(self):
        result = self.router.register("uaid", self.router_data)
        eq_(result, self.router_data)

    def test_register_bad(self):
        self.assertRaises(RouterException, self.router.register, "uaid", {})

    def test_route_notification(self):
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            self.mock_apns.gateway_server.send_notification.assert_called()

        d.addCallback(check_results)
        return d

    def test_message_pruning(self):
        self.router.messages = {1: {'token': 'dump', 'payload': {}}}
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            self.mock_apns.gateway_server.send_notification.assert_called()
            eq_(len(self.router.messages), 1)
        d.addCallback(check_results)
        return d

    def test_response_listener_with_success(self):
        self.router.messages = {1: {'token': 'dump', 'payload': {}}}
        self.router._error(dict(status=0, identifier=1))
        eq_(len(self.router.messages), 0)

    def test_response_listener_with_nonretryable_error(self):
        self.router.messages = {1: {'token': 'dump', 'payload': {}}}
        self.router._error(dict(status=2, identifier=1))
        eq_(len(self.router.messages), 1)

    def test_response_listener_with_retryable_existing_message(self):
        self.router.messages = {1: {'token': 'dump', 'payload': {}}}
        # Mock out the _connect call to be harmless
        self.router._connect = Mock()
        self.router._error(dict(status=1, identifier=1))
        eq_(len(self.router.messages), 1)
        self.router.apns.gateway_server.send_notification.assert_called()

    def test_response_listener_with_retryable_non_existing_message(self):
        self.router.messages = {1: {'token': 'dump', 'payload': {}}}
        self.router._error(dict(status=1, identifier=10))
        eq_(len(self.router.messages), 1)


class GCMRouterTestCase(unittest.TestCase):
    def setUp(self):
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        # Mock out GCM client
        self._old_gcm = gcmclient.GCM
        gcmclient.GCM = Mock(spec=gcmclient.GCM)

        apns_config = {'cert_file': 'fake.cert', 'key_file': 'fake.key'}
        self.router = GCMRouter(settings, apns_config)
        self.notif = Notification(10, "data", dummy_chid)
        self.router_data = dict(token="connect_data")
        mock_result = Mock(spec=gcmclient.gcm.Result)
        mock_result.canonical = dict()
        mock_result.failed = dict()
        mock_result.not_registered = dict()
        mock_result.needs_retry.return_value = False
        self.mock_result = mock_result
        self.router.gcm.send.return_value = mock_result

    def tearDown(self):
        gcmclient.GCM = self._old_gcm

    def test_register(self):
        result = self.router.register("uaid", self.router_data)
        eq_(result, self.router_data)

    def test_register_bad(self):
        self.assertRaises(RouterException, self.router.register, "uaid", {})

    def test_router_notification(self):
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            self.router.gcm.send.assert_called()
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_auth_error(self):
        def throw_auth(arg):
            raise gcmclient.GCMAuthenticationError()
        self.router.gcm.send.side_effect = throw_auth
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            exc = fail.value
            ok_(isinstance(exc, RouterException))
            eq_(exc.status_code, 500)
            self.router.gcm.send.assert_called()
            self.flushLoggedErrors()
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_other_error(self):
        def throw_other(arg):
            raise Exception("oh my!")
        self.router.gcm.send.side_effect = throw_other
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            exc = fail.value
            ok_(isinstance(exc, RouterException))
            eq_(exc.status_code, 500)
            self.router.gcm.send.assert_called()
            self.flushLoggedErrors()
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_id_change(self):
        self.mock_result.canonical["old"] = "new"
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict(token="new"))
            self.router.gcm.send.assert_called()
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_not_regged(self):
        self.mock_result.not_registered = {"connect_data": True}
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict())
            self.router.gcm.send.assert_called()
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_failed_items(self):
        self.mock_result.failed = dict(connect_data=True)
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            exc = fail.value
            ok_(isinstance(exc, RouterException))
            eq_(exc.status_code, 503)
            self.router.gcm.send.assert_called()
            self.flushLoggedErrors()
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_needs_retry(self):
        self.mock_result.needs_retry.return_value = True
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            exc = fail.value
            ok_(isinstance(exc, RouterException))
            eq_(exc.status_code, 503)
            self.router.gcm.send.assert_called()
            self.flushLoggedErrors()
        d.addBoth(check_results)
        return d
