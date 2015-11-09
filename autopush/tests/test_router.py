# -*- coding: utf-8 -*-
from unittest import TestCase
import uuid

from mock import Mock, PropertyMock, patch
from moto import mock_dynamodb2, mock_s3
from nose.tools import eq_, ok_
from twisted.trial import unittest
from twisted.internet.error import ConnectError

import apns
import gcmclient

from autopush.db import (
    Router,
    Storage,
    Message,
    ProvisionedThroughputExceededException,
    ItemNotFound,
)
from autopush.endpoint import Notification
from autopush.router import APNSRouter, GCMRouter, SimpleRouter, WebPushRouter
from autopush.router.simple import dead_cache
from autopush.router.interface import RouterException, RouterResponse, IRouter
from autopush.settings import AutopushSettings


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_s3().start()
    mock_dynamodb2.start()


def tearDown():
    mock_s3().stop()
    mock_dynamodb2.stop()


class MockAssist(object):
    def __init__(self, results):
        self.cur = 0
        self.max = len(results)
        self.results = results

    def __call__(self, *args, **kwargs):
        try:
            r = self.results[self.cur]
            print r
            if callable(r):
                return r()
            else:
                return r
        finally:
            if self.cur < (self.max - 1):
                self.cur += 1


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
        self.assertRaises(NotImplementedError, ir.amend_msg, {})


dummy_chid = str(uuid.uuid4())
dummy_uaid = str(uuid.uuid4())


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
        self.notif = Notification(10, "data", dummy_chid, None, 200)
        self.router_data = dict(router_data=dict(token="connect_data"))

    def test_register(self):
        result = self.router.register("uaid", {"token": "connect_data"})
        eq_(result, {"token": "connect_data"})

    def test_register_bad(self):
        self.assertRaises(RouterException, self.router.register, "uaid", {})

    def test_route_notification(self):
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            assert(self.mock_apns.gateway_server.send_notification.called)

        d.addCallback(check_results)
        return d

    def test_message_pruning(self):
        self.router.messages = {1: {'token': 'dump', 'payload': {}}}
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            assert(self.mock_apns.gateway_server.send_notification.called)
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
        assert(self.router.apns.gateway_server.send_notification.called)

    def test_response_listener_with_retryable_non_existing_message(self):
        self.router.messages = {1: {'token': 'dump', 'payload': {}}}
        self.router._error(dict(status=1, identifier=10))
        eq_(len(self.router.messages), 1)

    def test_ammend(self):
        resp = {"key": "value"}
        eq_(resp, self.router.amend_msg(resp))


class GCMRouterTestCase(unittest.TestCase):

    @patch("gcmclient.gcm.GCM", spec=gcmclient.gcm.GCM)
    def setUp(self, fgcm):
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        gcm_config = {'s3_bucket': 'oms_autopush_test',
                      'senderid_list': {'test123':
                                        {"auth": "12345678abcdefg"}}}
        self.gcm = fgcm
        self.router = GCMRouter(settings, gcm_config)
        self.notif = Notification(10, "data", dummy_chid, None, 200)
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

    def _check_error_call(self, exc, code):
        ok_(isinstance(exc, RouterException))
        eq_(exc.status_code, code)
        assert(self.router.gcm.send.called)
        self.flushLoggedErrors()

    def test_init(self):
        self.router.senderIDs.get_ID = Mock()

        def throw_ex():
            raise AttributeError
        fsenderids = Mock()
        fsenderids.choose_ID.side_effect = throw_ex
        self.assertRaises(IOError, GCMRouter, {}, {"senderIDs": fsenderids})

    def test_register(self):
        result = self.router.register("uaid", {"token": "connect_data"})
        # Check the information that will be recorded for this user
        eq_(result, {"token": "connect_data",
                     "creds": {"senderID": "test123",
                               "auth": "12345678abcdefg"}})

    def test_register_bad(self):
        self.assertRaises(RouterException, self.router.register, "uaid", {})

    def test_route_notification(self):
        self.router.gcm = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            assert(self.router.gcm.send.called)
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_auth_error(self):
        def throw_auth(arg):
            raise gcmclient.GCMAuthenticationError()
        self.gcm.send.side_effect = throw_auth
        self.router.gcm = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_other_error(self):
        def throw_other(arg):
            raise Exception("oh my!")
        self.gcm.send.side_effect = throw_other
        self.router.gcm = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 500)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_id_change(self):
        self.mock_result.canonical["old"] = "new"
        self.router.gcm = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict(token="new"))
            assert(self.router.gcm.send.called)
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_not_regged(self):
        self.mock_result.not_registered = {"connect_data": True}
        self.router.gcm = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.router_data, dict())
            assert(self.router.gcm.send.called)
        d.addCallback(check_results)
        return d

    def test_router_notification_gcm_failed_items(self):
        self.mock_result.failed = dict(connect_data=True)
        self.router.gcm = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 503)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_needs_retry(self):
        self.mock_result.needs_retry.return_value = True
        self.router.gcm = self.gcm
        d = self.router.route_notification(self.notif, self.router_data)

        def check_results(fail):
            self._check_error_call(fail.value, 503)
        d.addBoth(check_results)
        return d

    def test_router_notification_gcm_no_auth(self):
        d = self.router.route_notification(self.notif,
                                           {"router_data": {"token": "abc"}})

        def check_results(fail):
            eq_(fail.value.status_code, 500)
        d.addBoth(check_results)
        return d

    def test_ammend(self):
        self.router.register("uaid", {"token": "connect_data"})
        resp = {"key": "value"}
        eq_({"key": "value", "senderid": "test123"},
            self.router.amend_msg(resp))


class SimplePushRouterTestCase(unittest.TestCase):
    def setUp(self):
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )

        self.router = SimpleRouter(settings, {})
        self.notif = Notification(10, "data", dummy_chid, None, 200)
        mock_result = Mock(spec=gcmclient.gcm.Result)
        mock_result.canonical = dict()
        mock_result.failed = dict()
        mock_result.not_registered = dict()
        mock_result.needs_retry.return_value = False
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.agent_mock = Mock(spec=settings.agent)
        settings.agent = self.agent_mock
        self.router.metrics = Mock()

    def tearDown(self):
        dead_cache.clear()

    def _raise_connect_error(self):
        raise ConnectError()

    def _raise_db_error(self):
        raise ProvisionedThroughputExceededException(None, None)

    def _raise_item_error(self):
        raise ItemNotFound()

    def test_register(self):
        r = self.router.register(None, {})
        eq_(r, {})

    def test_route_to_connected(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.code = 200
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 200)
        d.addBoth(verify_deliver)
        return d

    def test_route_connect_error(self):
        self.agent_mock.request.side_effect = MockAssist(
            [self._raise_connect_error])
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.clear_node.return_value = None
        d = self.router.route_notification(self.notif, router_data)

        def verify_retry(fail):
            exc = fail.value
            ok_(exc, RouterException)
            eq_(exc.status_code, 503)
            eq_(len(self.router_mock.clear_node.mock_calls), 1)
            self.router_mock.clear_node.reset_mock()
            self.flushLoggedErrors()

        def verify_deliver(fail):
            exc = fail.value
            ok_(exc, RouterException)
            eq_(exc.status_code, 503)
            eq_(len(self.router_mock.clear_node.mock_calls), 1)
            self.router_mock.clear_node.reset_mock()
            d = self.router.route_notification(self.notif, router_data)
            d.addBoth(verify_retry)
            return d
        d.addBoth(verify_deliver)
        return d

    def test_route_to_busy_node_save_old_version(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.code = 202
        self.storage_mock.save_notification.return_value = False
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 202)
        d.addBoth(verify_deliver)
        return d

    def test_route_to_busy_node_save_throws_db_error(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.code = 202
        self.storage_mock.save_notification.side_effect = MockAssist(
            [self._raise_db_error]
        )
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(fail):
            exc = fail.value
            ok_(exc, RouterException)
            eq_(exc.status_code, 503)
        d.addBoth(verify_deliver)
        return d

    def test_route_with_no_node_saves_and_lookup_fails(self):
        self.storage_mock.save_notification.return_value = True
        self.router_mock.get_uaid.side_effect = MockAssist(
            [self._raise_db_error]
        )
        router_data = dict(uaid=dummy_uaid)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 202)
        d.addBoth(verify_deliver)
        return d

    def test_route_with_no_node_saves_and_lookup_fails_with_item_error(self):
        self.storage_mock.save_notification.return_value = True
        self.router_mock.get_uaid.side_effect = MockAssist(
            [self._raise_item_error]
        )
        router_data = dict(uaid=dummy_uaid)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(fail):
            exc = fail.value
            ok_(exc, RouterException)
            eq_(exc.status_code, 404)
        d.addBoth(verify_deliver)
        return d

    def test_route_to_busy_node_saves_looks_up_and_no_node(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.code = 202
        self.storage_mock.save_notification.return_value = True
        self.router_mock.get_uaid.return_value = dict()
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 202)
        d.addBoth(verify_deliver)
        return d

    def test_route_to_busy_node_saves_looks_up_and_sends_check_202(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.code = 202
        self.storage_mock.save_notification.return_value = True
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.get_uaid.return_value = router_data

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 202)
            assert(self.router_mock.get_uaid.called)
        d.addBoth(verify_deliver)
        return d

    def test_route_to_busy_node_saves_looks_up_and_send_check_fails(self):
        import autopush.router.simple as simple
        response_mock = Mock()
        self.agent_mock.request.side_effect = MockAssist(
            [response_mock, self._raise_connect_error])
        response_mock.code = 202
        self.storage_mock.save_notification.return_value = True
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.get_uaid.return_value = router_data

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 202)
            assert(self.router_mock.clear_node.called)
            nk = simple.node_key(router_data["node_id"])
            eq_(simple.dead_cache.get(nk), True)
        d.addBoth(verify_deliver)
        return d

    def test_route_busy_node_saves_looks_up_and_send_check_fails_and_db(self):
        import autopush.router.simple as simple
        response_mock = Mock()
        self.agent_mock.request.side_effect = MockAssist(
            [response_mock, self._raise_connect_error])
        response_mock.code = 202
        self.storage_mock.save_notification.return_value = True
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.get_uaid.return_value = router_data
        self.router_mock.clear_node.side_effect = MockAssist(
            [self._raise_db_error]
        )

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 202)
            assert(self.router_mock.clear_node.called)
            nk = simple.node_key(router_data["node_id"])
            eq_(simple.dead_cache.get(nk), True)
        d.addBoth(verify_deliver)
        return d

    def test_route_to_busy_node_saves_looks_up_and_sends_check_200(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.addCallback.return_value = response_mock
        type(response_mock).code = PropertyMock(
            side_effect=MockAssist([202, 200]))
        self.storage_mock.save_notification.return_value = True
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.get_uaid.return_value = router_data

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 200)
            self.router.metrics.increment.assert_called_with(
                "router.broadcast.save_hit"
            )
        d.addBoth(verify_deliver)
        return d

    @patch("requests.post")
    def test_route_udp(self, request_mock):
        self.storage_mock.save_notification.return_value = True
        udp_data = {'wakeup_host': {'ip': '127.0.0.1', 'port': 9999},
                    'mobilenetwork': {'mcc': 'hammer'}}
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid,
                           udp=udp_data)
        self.router_mock.get_uaid.return_value = router_data
        self.router.conf = {'server': 'http://example.com',
                            'idle': 1, 'cert': 'test.pem'}

        d = self.router.route_notification(self.notif, router_data)

        def check_deliver(result):
            eq_(result.status_code, 202)

        d.addBoth(check_deliver)
        eq_(self.router.udp, udp_data)
        return d

    def test_ammend(self):
        resp = {"key": "value"}
        eq_(resp, self.router.amend_msg(resp))


class WebPushRouterTestCase(unittest.TestCase):
    def setUp(self):
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )

        self.headers = headers = {
            "content-encoding": "aes128",
            "encryption": "awesomecrypto",
            "encryption-key": "niftykey"
        }
        self.router = WebPushRouter(settings, {})
        self.notif = Notification(10, "data", dummy_chid, headers, 20)
        mock_result = Mock(spec=gcmclient.gcm.Result)
        mock_result.canonical = dict()
        mock_result.failed = dict()
        mock_result.not_registered = dict()
        mock_result.needs_retry.return_value = False
        self.router_mock = settings.router = Mock(spec=Router)
        self.message_mock = settings.message = Mock(spec=Message)
        self.agent_mock = Mock(spec=settings.agent)
        settings.agent = self.agent_mock
        self.router.metrics = Mock()

    def test_route_to_busy_node_saves_looks_up_and_sends_check_201(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.addCallback.return_value = response_mock
        type(response_mock).code = PropertyMock(
            side_effect=MockAssist([202, 200]))
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = [dummy_chid]
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.get_uaid.return_value = router_data
        self.router.message_id = uuid.uuid4().hex

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(result):
            ok_(isinstance(result, RouterResponse))
            eq_(result.status_code, 201)
            self.router.metrics.increment.assert_called_with(
                "router.broadcast.save_hit"
            )
            ok_("Location" in result.headers)
        d.addCallback(verify_deliver)
        return d

    def test_route_to_busy_node_with_ttl_zero(self):
        notif = Notification(10, "data", dummy_chid, self.headers, 0)
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.addCallback.return_value = response_mock
        type(response_mock).code = PropertyMock(
            side_effect=MockAssist([202, 200]))
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = [dummy_chid]
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.get_uaid.return_value = router_data
        self.router.message_id = uuid.uuid4().hex

        d = self.router.route_notification(notif, router_data)

        def verify_deliver(fail):
            exc = fail.value
            ok_(exc, RouterResponse)
            eq_(exc.status_code, 201)
            eq_(len(self.router.metrics.increment.mock_calls), 0)
            ok_("Location" not in exc.headers)
        d.addBoth(verify_deliver)
        return d

    def test_route_with_invalid_channel_id(self):
        self.agent_mock.request.return_value = response_mock = Mock()
        response_mock.addCallback.return_value = response_mock
        type(response_mock).code = PropertyMock(
            side_effect=MockAssist([202, 200]))
        self.message_mock.store_message.return_value = True
        self.message_mock.all_channels.return_value = []
        router_data = dict(node_id="http://somewhere", uaid=dummy_uaid)
        self.router_mock.get_uaid.return_value = router_data
        self.router.message_id = uuid.uuid4().hex

        d = self.router.route_notification(self.notif, router_data)

        def verify_deliver(fail):
            exc = fail.value
            ok_(exc, RouterException)
            eq_(exc.status_code, 404)
            self.flushLoggedErrors()
        d.addBoth(verify_deliver)
        return d

    def test_ammend(self):
        resp = {"key": "value"}
        eq_(resp, self.router.amend_msg(resp))
