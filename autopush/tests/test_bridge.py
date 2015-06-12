# -*- coding: utf-8 -*-
from mock import Mock, patch
from moto import mock_dynamodb2
from unittest import TestCase

import gcmclient
import apns

from autopush.bridge.bridge import (Bridge, BridgeUndefEx, BridgeFailEx)
from autopush.bridge.apns_ping import (APNSBridge)
from autopush.bridge.gcm_ping import (GCMBridge)

from twisted.internet import reactor


mock_dynamodb2 = mock_dynamodb2()


class BridgeTestCase(TestCase):

    f_gcm = Mock()
    f_apns = Mock()

    def setUp(self):
        mock_dynamodb2.start()
        self.r_gcm = gcmclient.GCM
        self.s_apns = apns.APNs

    def tearDown(self):
        mock_dynamodb2.stop()

    @patch.object(gcmclient, 'GCM', return_value=f_gcm)
    @patch.object(gcmclient, 'JSONMessage', return_value=f_gcm)
    @patch.object(apns, 'APNs', return_value=f_apns)
    def test_register(self, mapns=None, mgcmj=None, mgcm=None):
        settings = {'gcm': {'apikey': '12345678abcdefg'},
                    'apns': {'cert_file': 'fake.cert', 'key_file': 'fake.key'},
                    }
        storage = Mock()
        tping = Bridge(storage, settings)
        self.assertFalse(tping.register('uaid', None))
        tping.storage = None
        self.assertRaises(BridgeUndefEx, tping.register, 'uaid', 'connect')
        tping.storage = storage

        tping.storage.register_connect.return_value = True
        self.assertTrue(tping.register('uaid', 'connect'))

        tping.storage.register_connect.return_value = False
        self.assertRaises(BridgeFailEx, tping.register, 'uaid', 'connect')

        tping.storage.register_connect.side_effect = BridgeFailEx
        self.assertRaises(BridgeFailEx, tping.register, 'uaid', 'true')

    @patch.object(reactor, 'callLater', return_value=None)
    @patch.object(gcmclient, 'GCM', return_value=f_gcm)
    @patch.object(gcmclient, 'JSONMessage', return_value=f_gcm)
    @patch.object(apns, 'APNs', return_value=f_apns)
    def test_Ping(self, mapns=None, mgcmj=None, mgcm=None, mreactor=None):
        # no storage:
        settings = {'gcm': {'apikey': '12345678abcdefg'},
                    'apns': {'cert_file': 'fake.cert', 'key_file': 'fake.key'},
                    }
        self.assertRaises(BridgeUndefEx, Bridge, None, settings)

        # with storage:
        storage = Mock()
        storage.register_connect.return_value = True

        # bridge init doesn't actually use anything in storage, but it does
        # check to see if it's null as a sanity check
        tping = Bridge(storage, settings)
        mgcm.assert_called_with(settings['gcm']['apikey'])
        mapns.assert_called_with(
            use_sandbox=False,
            cert_file=settings['apns']['cert_file'],
            key_file=settings['apns']['key_file'],
            enhanced=True,
        )
        self.assertTrue(tping.gcm is not None)
        self.assertTrue(tping.apns is not None)

        # GCM test
        self.f_gcm.JSONMessage.return_value = "valid_json"
        self.f_gcm.send = Mock()
        self.f_gcm.send.return_value = Mock()
        self.f_gcm.send.return_value.failed.items = Mock()
        self.f_gcm.send.return_value.failed.items.return_value = []

        # no connect
        self.assertFalse(tping.ping("uaid", 123, 'abcd', None))
        self.assertFalse(tping.ping("uaid", 123, 'abcd', {"type": "foo"}))
        self.assertFalse(tping.ping("uaid", 123, 'abcd', {"type": "gcm"}))

        # Test sanity checks
        self.assertFalse(tping.gcm.ping("uaid", 123,
                                        'abcd', {"type": "foo"}))
        self.assertFalse(tping.gcm.ping("uaid", 123,
                                        'abcd', {"type": "gcm"}))
        self.assertFalse(tping.apns.ping("uaid", 123,
                                         'abcd', {"type": "foo"}))
        self.assertFalse(tping.apns.ping("uaid", 123,
                                         'abcd', {"type": "apns"}))
        self.f_gcm.send.return_value.canonical.items = Mock()
        self.f_gcm.send.return_value.canonical.items.return_value = []
        self.f_gcm.send.return_value.not_registered = []
        self.f_gcm.send.return_value.needs_retry.return_value = False
        reply = tping.ping("uaid", 123, 'abcd',
                           {"type": "gcm", "token": "abcd123"})
        self.assertTrue(reply)
        gcmclient.JSONMessage.assert_called_with(
            registration_ids=[u'abcd123'],
            collapse_key='simplepush',
            time_to_live=60,
            dry_run=False,
            data={'Msg': 'abcd', 'Ver': 123})

        self.f_gcm.send.return_value.failed.items.return_value = [1]
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         {"type": "gcm", "token": "abcd123"}))

        self.f_gcm.send.return_value.failed.items.return_value = []
        self.f_gcm.send.return_value.not_registered = [1]
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         {"type": "gcm", "token": "abcd123"}))

        self.f_gcm.send.return_value.not_registered = []
        self.f_gcm.send.return_value.canonical.items.return_value = [[1, 2]]
        self.assertTrue(tping.ping('uaid', 123, 'data',
                                   {"type": "gcm", "token": "abcd123"}))
        self.f_gcm.send.return_value.canonical.items.return_value = []

        # Payload value is Mock'd.
        self.f_gcm.send.return_value.needs_retry.return_value = True
        self.f_gcm.send.return_value.retry = Mock()
        self.f_gcm.send.return_value.retry.return_value = "payload"
        self.assertTrue(tping.ping('uaid', 123, 'data',
                                   {"type": "gcm", "token": "abcd123"}))

        self.f_gcm.send.side_effect = gcmclient.GCMAuthenticationError
        self.assertFalse(tping.ping('uaid', 123, 'data',
                                    {"type": "gcm", "token": "abcd123"}))
        mgcmj.side_effect = ValueError
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         {"type": "gcm", "token": "☃"}))
        self.f_gcm.send.side_effect = Exception
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         {"type": "gcm", "token": "abcd123"}))

        # APNs test
        apns.gateway_server = Mock()
        self.f_apns.gateway_server = Mock()
        self.f_apns.gateway_server.send_notification = Mock()
        reply = tping.ping("uaid", 123, 'abcd',
                           {"type": "apns", "token": "abcd123"})
        self.assertTrue(reply)
        # Need to find a better way to parse the second param of this
        _, (_, payload, _), _ = \
            self.f_apns.gateway_server.send_notification.mock_calls[0]
        self.assertEqual(payload.custom, {'Msg': 'abcd', 'Ver': 123})
        reply = tping.ping("uaid", 123, 'abcd',
                           {"type": "apns", "token": "abcd123"})
        self.assertTrue(reply)

        # Clear the messages so we can test autoprune.
        tping.apns.messages = {1: {'token': 'dump', 'payload': {}}}
        reply = tping.ping("uaid", 456, 'efgh',
                           {"type": "apns", "token": "keep123"})
        self.assertTrue(len(tping.apns.messages) and
                        tping.apns.messages.get(1) is None)
        self.f_apns.gateway_server.send_notification.side_effect = Exception
        reply = tping.ping("uaid", 123, 'abcd',
                           {"type": "apns", "token": "abcd123"})
        self.assertFalse(reply)

    @patch.object(gcmclient, 'GCM', return_value=f_gcm)
    def test_Ping_result(self, mgcm=None):
        storage = Mock()
        tgcm = GCMBridge({}, storage)
        reply = Mock()
        reply.canonical = Mock()
        reply.failed = Mock()
        reply.retry = Mock()
        reply.canonical.items.return_value = []
        reply.not_registered = []
        reply.failed.items.return_value = []
        reply.needs_retry.return_value = True
        reply.retry.return_value = "ignored"
        self.assertFalse(tgcm._result(reply, 6))

    @patch.object(apns, 'APNs', return_value=f_apns)
    def test_apns_error(self, mapns=None):
        settings = {'gcm': {'apikey': '12345678abcdefg'},
                    'apns': {'cert_file': 'fake.cert', 'key_file': 'fake.key'},
                    }
        storage = Mock()
        storage.register_connect.return_value = True
        tapns = APNSBridge(settings, storage)

        tapns.messages = {1: {}}
        tapns._error({'status': 0, 'identifier': 1})
        self.assertTrue(len(tapns.messages) == 0)
        self.f_apns.gateway_server = Mock()
        self.f_apns.gateway_server.send_notification = Mock()
        tapns.messages = {1: {'token': 'abcd', 'payload': '1234'},
                          }
        tapns._error({'status': 1, 'identifier': 1})
        self.f_apns.gateway_server.send_notification.assert_called_with(
            'abcd', '1234', 1)
        self.f_apns.gateway_server.send_notification = Mock()
        tapns._error({'status': 1})
        self.assertFalse(self.f_apns.gatemway_server.send_notification.called)

    @patch.object(gcmclient, 'GCM', return_value=f_gcm)
    @patch.object(gcmclient, 'JSONMessage', return_value=f_gcm)
    @patch.object(apns, 'APNs', return_value=f_apns)
    def test_unregister(self, mapns=None, mgcmj=None, mgcm=None):
        settings = {'gcm': {'apikey': '12345678abcdefg'},
                    'apns': {'cert_file': 'fake.cert', 'key_file': 'fake.key'},
                    }
        storage = Mock()
        tping = Bridge(storage, settings)
        tping.storage.unregister.return_value = True
        self.assertTrue(tping.unregister('uaid'))
        tping.storage.unregister.return_value = False
        self.assertFalse(tping.unregister('uaid'))
        tping.storage = None
        self.assertRaises(BridgeUndefEx, tping.unregister, 'uaid')
