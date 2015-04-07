import unittest

import twisted.internet.base

from nose.tools import ok_
from mock import Mock, patch

from datadog.util.hostname import get_hostname

from autopush.metrics import DatadogMetrics, TwistedMetrics


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
        hostname = get_hostname()

        m = DatadogMetrics("someapikey", "someappkey", namespace="testpush")
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
