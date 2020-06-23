import unittest

import pytest
from mock import Mock, patch, call

from autopush.metrics import (
    IMetrics,
    TaggedMetrics,
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


class TaggedMetricsTestCase(unittest.TestCase):
    @patch("autopush.metrics.markus")
    def test_basic(self, mock_tag):
        hostname = "localhost"

        m = TaggedMetrics(namespace="testpush", hostname="localhost")
        assert len(mock_tag.mock_calls) > 0
        m._client = Mock()
        m.start()
        m.increment("test", 5)
        # Namespace is now auto-prefixed by the underlying markus lib
        m._client.incr.assert_called_with("test", 5,
                                          host=hostname)
        m.gauge("connection_count", 200)
        m._client.gauge.assert_called_with("connection_count", 200,
                                           host=hostname)
        m.timing("lifespan", 113)
        m._client.timing.assert_called_with("lifespan", value=113,
                                            host=hostname)


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
