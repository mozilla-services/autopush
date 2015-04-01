# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from mock import Mock, patch
from moto import mock_dynamodb2
from unittest import TestCase

import gcmclient as gcm
import apns

from autopush.pinger.pinger import (Pinger, PingerUndefEx)


mock_dynamodb2 = mock_dynamodb2()


class PingerTestCase(TestCase):

    f_gcm = Mock()
    f_apns = Mock()

    def setUp(self):
        mock_dynamodb2.start()
        self.r_gcm = gcm.GCM
        self.s_apns = apns.APNs

    def tearDown(self):
        mock_dynamodb2.stop()

    @patch.object(gcm, 'GCM', return_value=f_gcm)
    @patch.object(gcm, 'JSONMessage', return_value=f_gcm)
    @patch.object(apns, 'APNs', return_value=f_apns)
    def test_register(self, mapns=None, mgcmj=None, mgcm=None):
        settings = {'gcm': {'apikey': '12345678abcdefg'},
                    'apns': {'cert_file': 'fake.cert', 'key_file': 'fake.key'},
                    }
        storage = Mock()
        tping = Pinger(storage, settings)
        self.assertFalse(tping.register('uaid', None))
        tping.storage = None
        self.assertRaises(PingerUndefEx, tping.register, 'uaid', 'connect')
        tping.storage = storage

        tping.storage.register_connect.return_value = True
        self.assertTrue(tping.register('uaid', 'connect'))

        tping.storage.register_connect.return_value = False
        self.assertFalse(tping.register('uaid', 'connect'))

        tping.storage.register_connect.side_effect = Exception
        self.assertFalse(tping.register('uaid', 'true'))

    @patch.object(gcm, 'GCM', return_value=f_gcm)
    @patch.object(gcm, 'JSONMessage', return_value=f_gcm)
    @patch.object(apns, 'APNs', return_value=f_apns)
    def test_Ping(self, mapns=None, mgcmj=None, mgcm=None):
        # no storage:
        settings = {'gcm': {'apikey': '12345678abcdefg'},
                    'apns': {'cert_file': 'fake.cert', 'key_file': 'fake.key'},
                    }
        self.assertRaises(PingerUndefEx, Pinger, None, settings)

        # with storage:
        storage = Mock()
        storage.register_connect.return_value = True

        # Pinger init doesn't actually use anything in storage, but it does
        # check to see if it's null as a sanity check
        tping = Pinger(storage, settings)
        mgcm.assert_called_with(settings['gcm']['apikey'])
        mapns.assert_called_with(
            use_sandbox=False,
            cert_file=settings['apns']['cert_file'],
            key_file=settings['apns']['key_file'],
        )
        self.assertTrue(tping.gcm is not None)
        self.assertTrue(tping.apns is not None)

        # GCM test
        class zfr:
            length = 0

        class rfr:
            length = 1
        self.f_gcm.JSONMessage.return_value = "valid_json"
        self.f_gcm.send = Mock()
        self.f_gcm.send.return_value = Mock()
        self.f_gcm.send.return_value.failed.items = Mock()
        self.f_gcm.send.return_value.failed.items.return_value = zfr

        # no connect
        self.assertFalse(tping.ping("uaid", 123, 'abcd', None))
        self.assertFalse(tping.ping("uaid", 123, 'abcd', '{"type":"foo"}'))
        self.assertFalse(tping.ping("uaid", 123, 'abcd', '{"type":"gcm"}'))

        # Test sanity checks
        self.assertFalse(tping.gcm.ping("uaid", 123,
                                        'abcd', {"type": "foo"}))
        self.assertFalse(tping.gcm.ping("uaid", 123,
                                        'abcd', {"type": "gcm"}))
        self.assertFalse(tping.apns.ping("uaid", 123,
                                         'abcd', {"type": "foo"}))
        self.assertFalse(tping.apns.ping("uaid", 123,
                                         'abcd', {"type": "apns"}))

        reply = tping.ping("uaid", 123, 'abcd',
                           '{"type":"gcm","token":"abcd123"}')
        self.assertTrue(reply)
        self.f_gcm.JSONMessage.assert_called_with(
            registration_ids=[u'abcd123'],
            collapse_key='simplepush',
            time_to_live=60,
            dry_run=False,
            data={'Msg': 'abcd', 'Version': 123})
        self.f_gcm.send.side_effect = gcm.GCMAuthenticationError
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         '{"type":"gcm", "token":"abcd123"}'))
        self.f_gcm.send.side_effect = ValueError
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         '{"type":"gcm", "token":"abcd123"}'))
        self.f_gcm.send.side_effect = Exception
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         '{"type":"gcm", "token":"abcd123"}'))
        self.f_gcm.send.side_effect = None
        self.f_gcm.send.return_value.failed.items.return_value = rfr
        self.assertFalse(tping.ping('uaid', 123, 'data',
                         '{"type":"gcm", "token":"abcd123"}'))
        self.f_gcm.send.return_value.failed.items.return_value = zfr

        # APNs test
        self.f_apns.gateway_server = Mock()
        reply = tping.ping("uaid", 123, 'abcd',
                           '{"type":"apns","token":"abcd123"}')
        self.assertTrue(reply)
        # Need to find a better way to parse the second param of this
        ca = str(self.f_apns.gateway_server.send_notification.call_args)
        rs = "custom={'Msg': 'abcd', 'Version': 123}"
        self.assertTrue(ca.find(rs) > -1)

        reply = tping.ping("uaid", 123, 'abcd',
                           '{"type":"apns","token":"abcd123"}')
        self.assertTrue(reply)

        self.f_apns.gateway_server.send_notification.side_effect = Exception
        reply = tping.ping("uaid", 123, 'abcd',
                           '{"type":"apns","token":"abcd123"}')
        self.assertFalse(reply)
        self.f_apns.gateway_server.send_notification.side_effect = None

    @patch.object(gcm, 'GCM', return_value=f_gcm)
    @patch.object(gcm, 'JSONMessage', return_value=f_gcm)
    @patch.object(apns, 'APNs', return_value=f_apns)
    def test_unregister(self, mapns=None, mgcmj=None, mgcm=None):
        settings = {'gcm': {'apikey': '12345678abcdefg'},
                    'apns': {'cert_file': 'fake.cert', 'key_file': 'fake.key'},
                    }
        storage = Mock()
        tping = Pinger(storage, settings)
        tping.storage.unregister.return_value = True
        self.assertTrue(tping.unregister('uaid'))
        tping.storage.unregister.return_value = False
        self.assertFalse(tping.unregister('uaid'))
        tping.storage = None
        self.assertRaises(PingerUndefEx, tping.unregister, 'uaid')
