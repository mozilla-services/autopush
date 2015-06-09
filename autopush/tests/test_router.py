# -*- coding: utf-8 -*-
from unittest import TestCase
import uuid

from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.trial import unittest

import apns

from autopush.endpoint import Notification
from autopush.router.apnsrouter import APNSRouter
from autopush.router.interface import RouterException, RouterResponse
from autopush.settings import AutopushSettings


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class RouterTestCase(TestCase):
    pass


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
