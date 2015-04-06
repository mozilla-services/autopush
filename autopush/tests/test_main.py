import unittest

from mock import patch
from moto import mock_dynamodb2

from autopush.main import connection_main, endpoint_main

mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class ConnectionMainTestCase(unittest.TestCase):
    def setUp(self):
        patchers = [
            "autopush.main.log",
            "autopush.main.task",
            "autopush.main.reactor",
            "autopush.settings.TwistedMetrics",
        ]
        self.mocks = {}
        for name in patchers:
            patcher = patch(name)
            self.mocks[name] = patcher.start()

    def tearDown(self):
        for mock in self.mocks.values():
            mock.stop()

    def test_basic(self):
        connection_main([])


class EndpointMainTestCase(unittest.TestCase):
    def setUp(self):
        patchers = [
            "autopush.main.log",
            "autopush.main.task",
            "autopush.main.reactor",
            "autopush.settings.TwistedMetrics",
        ]
        self.mocks = {}
        for name in patchers:
            patcher = patch(name)
            self.mocks[name] = patcher.start()

    def tearDown(self):
        for mock in self.mocks.values():
            mock.stop()

    def test_basic(self):
        endpoint_main([])
