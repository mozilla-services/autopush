"""Metrics interface and implementations"""
from typing import (  # noqa
    TYPE_CHECKING,
    Any,
    Optional,
    Sequence
)

from twisted.internet import reactor

import datadog
from datadog import ThreadStats

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


class DatadogMetrics(object):
    """DataDog Metric backend"""
    def __init__(self, api_key=None, app_key=None, hostname=None,
                 statsd_host=None, statsd_port=None, flush_interval=10,
                 namespace="autopush"):

        datadog.initialize(
            api_key=api_key,
            app_key=app_key,
            host_name=hostname,
            statsd_host=statsd_host,
            statsd_port=statsd_port,
        )
        self._client = ThreadStats()
        self._flush_interval = flush_interval
        self._host = hostname
        self._namespace = namespace

    def _prefix_name(self, name):
        return "%s.%s" % (self._namespace, name)

    def start(self):
        self._client.start(flush_interval=self._flush_interval,
                           roll_up_interval=self._flush_interval)

    def increment(self, name, count=1, **kwargs):
        self._client.increment(self._prefix_name(name), count, host=self._host,
                               **kwargs)

    def gauge(self, name, count, **kwargs):
        self._client.gauge(self._prefix_name(name), count, host=self._host,
                           **kwargs)

    def timing(self, name, duration, **kwargs):
        self._client.timing(self._prefix_name(name), value=duration,
                            host=self._host, **kwargs)


def from_config(conf):
    # type: (AutopushConfig) -> IMetrics
    """Create an IMetrics from the given config"""
    if conf.statsd_host:
        return DatadogMetrics(
            hostname=logging.instance_id_or_hostname if conf.ami_id else
            conf.hostname,
            statsd_host=conf.statsd_host,
            statsd_port=conf.statsd_port,
            flush_interval=conf.datadog_flush_interval,
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
