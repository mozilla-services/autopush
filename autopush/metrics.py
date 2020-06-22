"""Metrics interface and implementations"""
from typing import (  # noqa
    TYPE_CHECKING,
    Any,
    Optional,
    Sequence
)

from twisted.internet import reactor
from txstatsd.client import StatsDClientProtocol, TwistedStatsDClient
from txstatsd.metrics.metrics import Metrics

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


class TwistedMetrics(object):
    """Twisted implementation of statsd output"""
    def __init__(self, statsd_host="localhost", statsd_port=8125):
        self.client = TwistedStatsDClient(statsd_host, statsd_port)
        self._metric = Metrics(connection=self.client, namespace="autopush")

    def make_tags(self, base=None, **kwargs):
        return kwargs

    def start(self):
        protocol = StatsDClientProtocol(self.client)
        reactor.listenUDP(0, protocol)

    def increment(self, name, count=1, **kwargs):
        self._metric.increment(name, count)

    def gauge(self, name, count, **kwargs):
        self._metric.gauge(name, count)

    def timing(self, name, duration, **kwargs):
        self._metric.timing(name, duration)


class TaggedMetrics(object):
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
        # return "%s.%s" % (self._namespace, name)

    def start(self):
        pass

    def increment(self, name, count=1, **kwargs):
        self._client.incr(self._prefix_name(name), count, host=self._host,
                          **kwargs)

    def gauge(self, name, count, **kwargs):
        self._client.gauge(self._prefix_name(name), count, host=self._host,
                           **kwargs)

    def timing(self, name, duration, **kwargs):
        self._client.timing(self._prefix_name(name), value=duration,
                            host=self._host,
                            **kwargs)


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
