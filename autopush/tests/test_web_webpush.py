import uuid

from cryptography.fernet import Fernet
from cyclone.web import Application
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.internet.defer import Deferred
from twisted.logger import Logger
from twisted.trial import unittest

from autopush.db import (
    Router,
    create_rotating_message_table,
)
from autopush.router.interface import IRouter, RouterResponse
from autopush.settings import AutopushSettings

dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))
dummy_token = dummy_uaid + ":" + dummy_chid
mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()
    create_rotating_message_table()


def tearDown():
    mock_dynamodb2.stop()


class TestWebpushHandler(unittest.TestCase):
    def setUp(self):
        from autopush.web.webpush import WebPushHandler

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
        )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.ap_settings = settings

        self.router_mock = settings.router = Mock(spec=Router)
        self.request_mock = Mock(body=b'', arguments={},
                                 headers={"ttl": "0"},
                                 host='example.com:8080')

        self.wp = WebPushHandler(Application(),
                                 self.request_mock,
                                 ap_settings=settings)
        self.wp.path_kwargs = {}
        self.status_mock = self.wp.set_status = Mock()
        self.write_mock = self.wp.write = Mock()
        self.wp.log = Mock(spec=Logger)
        d = self.finish_deferred = Deferred()
        self.wp.finish = lambda: d.callback(True)
        settings.routers["webpush"] = Mock(spec=IRouter)
        self.wp_router_mock = settings.routers["webpush"]

    def test_router_needs_update(self):
        self.ap_settings.parse_endpoint = Mock(return_value=dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="asdfasdf",
        ))
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict(
            router_type="webpush",
            router_data=dict(),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=503,
            router_data=dict(token="new_connect"),
        )

        def handle_finish(result):
            eq_(result, True)
            self.wp.set_status.assert_called_with(503)
            ru = self.router_mock.register_user
            ok_(ru.called)
            eq_('webpush', ru.call_args[0][0].get('router_type'))

        self.finish_deferred.addCallback(handle_finish)

        self.wp.post("v1", dummy_token)
        return self.finish_deferred

    def test_router_returns_data_without_detail(self):
        self.ap_settings.parse_endpoint = Mock(return_value=dict(
            uaid=dummy_uaid,
            chid=dummy_chid,
            public_key="asdfasdf",
        ))
        self.fernet_mock.decrypt.return_value = dummy_token
        self.router_mock.get_uaid.return_value = dict(
            uaid=dummy_uaid,
            router_type="webpush",
            router_data=dict(uaid="uaid"),
        )
        self.wp_router_mock.route_notification.return_value = RouterResponse(
            status_code=503,
            router_data=dict(),
        )

        def handle_finish(result):
            eq_(result, True)
            self.wp.set_status.assert_called_with(503)
            ok_(self.router_mock.drop_user.called)

        self.finish_deferred.addCallback(handle_finish)

        self.wp.post("v1", dummy_token)
        return self.finish_deferred
