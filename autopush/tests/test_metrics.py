import unittest

import twisted.internet.base
import pytest
from mock import Mock, patch, call

from autopush.metrics import (
    IMetrics,
    DatadogMetrics,
    TwistedMetrics,
    SinkMetrics,
    periodic_reporter,
)


class IMetricsTestCase(unittest.TestCase):
    def test_default(self):
        im = IMetrics()
        im.start()
        with pytest.raises(NotImplementedError):
            im.increment("test")
        with pytest.raises(NotImplementedError):
            im.gauge("test", 10)
        with pytest.raises(NotImplementedError):
            im.timing("test", 10)


class SinkMetricsTestCase(unittest.TestCase):
    def test_passing(self):
        sm = SinkMetrics()
        sm.start()
        assert sm.increment("test") is None
        assert sm.gauge("test", 10) is None
        assert sm.timing("test", 10) is None


class TwistedMetricsTestCase(unittest.TestCase):
    @patch("autopush.metrics.reactor")
    def test_basic(self, mock_reactor):
        twisted.internet.base.DelayedCall.debug = True
        m = TwistedMetrics('127.0.0.1')
        m.start()
        assert len(mock_reactor.mock_calls) > 0
        m._metric = Mock()
        m.increment("test", 5)
        m._metric.increment.assert_called_with("test", 5, tags=None)
        m.gauge("connection_count", 200)
        m._metric.gauge.assert_called_with("connection_count", 200, tags=None)
        m.timing("lifespan", 113)
        m._metric.timing.assert_called_with("lifespan", 113, tags=None)

    @patch("autopush.metrics.reactor")
    def test_tags(self, mock_reactor):
        twisted.internet.base.DelayedCall.debug = True
        m = TwistedMetrics('127.0.0.1')
        m.start()
        assert len(mock_reactor.mock_calls) > 0
        m._metric = Mock()
        m.increment("test", 5, tags=["foo:bar"])
        m._metric.increment.assert_called_with("test", 5, tags=["foo:bar"])
        m.gauge("connection_count", 200, tags=["foo:bar", "baz:quux"])
        m._metric.gauge.assert_called_with("connection_count", 200,
                                           tags=["foo:bar", "baz:quux"])


class DatadogMetricsTestCase(unittest.TestCase):
    @patch("autopush.metrics.datadog")
    def test_basic(self, mock_dog):
        hostname = "localhost"

        m = DatadogMetrics("someapikey", "someappkey", namespace="testpush",
                           hostname="localhost")
        assert len(mock_dog.mock_calls) > 0
        m._client = Mock()
        m.start()
        m._client.start.assert_called_with(flush_interval=10,
                                           roll_up_interval=10)
        m.increment("test", 5)
        m._client.increment.assert_called_with("testpush.test", 5,
                                               host=hostname,
                                               tags=None)
        m.gauge("connection_count", 200)
        m._client.gauge.assert_called_with("testpush.connection_count", 200,
                                           host=hostname,
                                           tags=None)
        m.timing("lifespan", 113)
        m._client.timing.assert_called_with("testpush.lifespan", value=113,
                                            host=hostname,
                                            tags=None)


class PeriodicReporterTestCase(unittest.TestCase):

    def test_periodic_reporter(self):
        metrics = Mock(spec=SinkMetrics)
        periodic_reporter(metrics)
        periodic_reporter(metrics, prefix='foo')
        metrics.gauge.assert_has_calls([
            call('twisted.threadpool.idleWorkerCount', 0),
            call('twisted.threadpool.busyWorkerCount', 0),
            call('twisted.threadpool.backloggedWorkCount', 0),
            call('foo.twisted.threadpool.idleWorkerCount', 0),
            call('foo.twisted.threadpool.busyWorkerCount', 0),
            call('foo.twisted.threadpool.backloggedWorkCount', 0),
        ])
