"""Metrics interface and implementations"""
import time
import threading
from typing import (  # noqa
    TYPE_CHECKING,
    Any,
    Optional,
    Sequence
)

from twisted.internet import reactor
from twisted.logger import Logger
import markus

from autopush import logging

if TYPE_CHECKING:  # pragma: nocover
    from autopush.config import AutopushConfig  # noqa


log = Logger()


class IMetrics(object):
    """Metrics interface

    Each method except :meth:`__init__` and :meth:`start` must be implemented.

    Additional ``kwargs`` may be recorded as additional metric tags for metric
    systems that support it, otherwise they should be ignored.

    """
    def __init__(self, *args, **kwargs):
        """Setup the metrics"""

    def start(self):
        """Start any connection needed for metric transmission"""

    def increment(self, name, count=1, **kwargs):
        """Increment a counter for a metric name"""
        raise NotImplementedError("No increment implemented")

    def gauge(self, name, count, **kwargs):
        """Record a gauge for a metric name"""
        raise NotImplementedError("No gauge implemented")

    def timing(self, name, duration, **kwargs):
        """Record a timing in ms for a metric name"""
        raise NotImplementedError("No timing implemented")


class SinkMetrics(IMetrics):
    """Exists to ignore metrics when metrics are not active"""
    def increment(self, name, count=1, **kwargs):
        pass

    def gauge(self, name, count, **kwargs):
        pass

    def timing(self, name, duration, **kwargs):
        pass


def make_tags(base=None, **kwargs):
    # type: (Sequence[str], **Any) -> Sequence[str]
    """Generate a list of tag values"""
    tags = list(base or [])
    tags.extend('{}:{}'.format(key, val) for key, val in kwargs.iteritems())
    return tags


class TaggedMetrics(IMetrics):
    """DataDog like tagged Metric backend"""
    def __init__(self, hostname, statsd_host=None, statsd_port=None,
                 namespace="autopush", flush_interval=10):
        markus.configure(
            backends=[{
                'class': 'markus.backends.datadog.DatadogMetrics',
                'options': {
                    'statsd_host': statsd_host,
                    'statsd_port': statsd_port,
                }}])
        self._client = markus.get_metrics(namespace)
        self._host = hostname
        self._namespace = namespace

        self._metrics = []
        self._flush_interval = flush_interval
        self._thread = None
        self._lock = threading.RLock()

        self.start()

    def _prefix_name(self, name):
        return name

    def start(self):

        def flush_thread():
            while True:
                try:
                    self._flush()
                except Exception:
                    log.failure("Error flushing metrics")
                time.sleep(self._flush_interval)
        self._thread = thread = threading.Thread(target=flush_thread)
        thread.daemon = True
        thread.start()

    def _flush(self):
        with self._lock:
            metrics = self._metrics
            self._metrics = []
        for (fn, name, kwargs) in metrics:
            fn(name, **kwargs)

    def _make_tags(self, tags):
        if tags is None:
            tags = []
        tags.append('host:%s' % self._host)
        return tags

    def _queue_metric(self, fn, name, **kwargs):
        with self._lock:
            self._metrics.append((fn, name, kwargs))

    def increment(self, name, count=1, tags=None, **kwargs):
        self._queue_metric(
            self._client.incr,
            self._prefix_name(name),
            value=count,
            tags=self._make_tags(tags)
        )

    def gauge(self, name, count, tags=None, **kwargs):
        self._queue_metric(
            self._client.gauge,
            self._prefix_name(name),
            value=count,
            tags=self._make_tags(tags)
        )

    def timing(self, name, duration, tags=None, **kwargs):
        self._queue_metric(
            self._client.timing,
            self._prefix_name(name),
            value=duration,
            tags=self._make_tags(tags)
        )


def from_config(conf):
    # type: (AutopushConfig) -> IMetrics
    """Create an IMetrics from the given config"""
    if conf.statsd_host:
        return TaggedMetrics(
            hostname=logging.instance_id_or_hostname if conf.ami_id else
            conf.hostname,
            statsd_host=conf.statsd_host,
            statsd_port=conf.statsd_port,
        )
    else:
        return SinkMetrics()


def periodic_reporter(metrics, prefix=''):
    # type: (IMetrics, Optional[str]) -> None
    """Emit metrics on twisted's thread pool.

    Only meant to be called via a LoopingCall (TimerService).

    """
    # unfortunately stats only available via the private '_team'
    stats = reactor.getThreadPool()._team.statistics()
    for attr in ('idleWorkerCount', 'busyWorkerCount', 'backloggedWorkCount'):
        name = '{}{}twisted.threadpool.{}'.format(
            prefix,
            '.' if prefix else '',
            attr
        )
        metrics.gauge(name, getattr(stats, attr))
