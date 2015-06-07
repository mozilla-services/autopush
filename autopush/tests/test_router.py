# -*- coding: utf-8 -*-
from mock import Mock
from moto import mock_dynamodb2
from unittest import TestCase

import gcmclient
import apns


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class RouterTestCase(TestCase):

    f_gcm = Mock()
    f_apns = Mock()

    def setUp(self):
        self.r_gcm = gcmclient.GCM
        self.s_apns = apns.APNs
