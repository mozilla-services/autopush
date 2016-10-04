import unittest

import twisted.internet.base

from nose.tools import assert_raises, ok_, eq_
from mock import Mock, patch

from autopush.metrics import (
    IMetrics,
    DatadogMetrics,
    TwistedMetrics,
    SinkMetrics,
)


class IMetricsTestCase(unittest.TestCase):
    def test_default(self):
        im = IMetrics()
        im.start()
        assert_raises(NotImplementedError, im.increment, "test")
        assert_raises(NotImplementedError, im.gauge, "test", 10)
        assert_raises(NotImplementedError, im.timing, "test", 10)


class SinkMetricsTestCase(unittest.TestCase):
    def test_passing(self):
        sm = SinkMetrics()
        sm.start()
        eq_(None, sm.increment("test"))
        eq_(None, sm.gauge("test", 10))
        eq_(None, sm.timing("test", 10))


class TwistedMetricsTestCase(unittest.TestCase):
    @patch("autopush.metrics.reactor")
    def test_basic(self, mock_reactor):
        twisted.internet.base.DelayedCall.debug = True
        m = TwistedMetrics()
        m.start()
        ok_(len(mock_reactor.mock_calls) > 0)
        m._metric = Mock()
        m.increment("test", 5)
        m._metric.increment.assert_called_with("test", 5)
        m.gauge("connection_count", 200)
        m._metric.gauge.assert_called_with("connection_count", 200)
        m.timing("lifespan", 113)
        m._metric.timing.assert_called_with("lifespan", 113)


class DatadogMetricsTestCase(unittest.TestCase):
    @patch("autopush.metrics.datadog")
    def test_basic(self, mock_dog):
        hostname = "localhost"

        m = DatadogMetrics("someapikey", "someappkey", namespace="testpush",
                           hostname="localhost")
        ok_(len(mock_dog.mock_calls) > 0)
        m._client = Mock()
        m.start()
        m._client.start.assert_called_with(flush_interval=10,
                                           roll_up_interval=10)
        m.increment("test", 5)
        m._client.increment.assert_called_with("testpush.test", 5,
                                               host=hostname)
        m.gauge("connection_count", 200)
        m._client.gauge.assert_called_with("testpush.connection_count", 200,
                                           host=hostname)
        m.timing("lifespan", 113)
        m._client.timing.assert_called_with("testpush.lifespan", value=113,
                                            host=hostname)
