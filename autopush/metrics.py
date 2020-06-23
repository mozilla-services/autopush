"""Metrics interface and implementations"""
from typing import (  # noqa
    TYPE_CHECKING,
    Any,
    Optional,
    Sequence
)

from twisted.internet import reactor

import markus

from autopush import logging

if TYPE_CHECKING:  # pragma: nocover
    from autopush.config import AutopushConfig  # noqa


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

    def make_tags(self, base=None, **kwargs):
        """ convert tags if needed """

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

    def make_tags(self, base=None, **kwargs):
        pass

    def gauge(self, name, count, **kwargs):
        pass

    def timing(self, name, duration, **kwargs):
        pass


class TaggedMetrics(IMetrics):
    """DataDog like tagged Metric backend"""
    def __init__(self, hostname, namespace="autopush"):

        markus.configure(
            backends=[{
                'class': 'markus.backends.datadog.DatadogMetrics',
                'options': {
                    'statsd_host': hostname,
                    'statsd_namespace': namespace,
                }}])
        self._client = markus.get_metrics(namespace)
        self._host = hostname
        self._namespace = namespace

    def _prefix_name(self, name):
        return name

    def start(self):
        pass

    def make_tags(self, base=None, **kwargs):
        if "host" not in kwargs:
            kwargs["host"] = self._host
        if base is None:
            base = {}
        base.update(kwargs)
        return base

    def increment(self, name, count=1, tags=None, **kwargs):
        tags = self.make_tags(tags, **kwargs)
        self._client.incr(self._prefix_name(name), count, **tags)

    def gauge(self, name, count, tags=None, **kwargs):
        tags = self.make_tags(tags, **kwargs)
        self._client.gauge(self._prefix_name(name), count, **tags)

    def timing(self, name, duration, tags=None, **kwargs):
        tags = self.make_tags(tags, **kwargs)
        self._client.timing(self._prefix_name(name), value=duration,
                            **tags)


def from_config(conf):
    # type: (AutopushConfig) -> IMetrics
    """Create an IMetrics from the given config"""
    if conf.statsd_host:
        return TaggedMetrics(
            hostname=logging.instance_id_or_hostname if conf.ami_id else
            conf.hostname
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
