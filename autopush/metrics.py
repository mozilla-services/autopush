from twisted.internet import reactor
from txstatsd.client import StatsDClientProtocol, TwistedStatsDClient
from txstatsd.metrics.metrics import Metrics

import datadog
from datadog import ThreadStats
from datadog.util.hostname import get_hostname


class TwistedMetrics(object):
    def __init__(self, statsd_host="localhost", statsd_port=8125):
        self.client = TwistedStatsDClient(statsd_host, statsd_port)
        self._metric = Metrics(connection=self.client, namespace="pushgo")

    def start(self):
        protocol = StatsDClientProtocol(self.client)
        reactor.listenUDP(0, protocol)

    def increment(self, name, count=1, **kwargs):
        self._metric.increment(name, count)

    def gauge(self, name, count, **kwargs):
        self._metric.gauge(name, count)

    def timing(self, name, duration):
        self._metric.timing(name, duration)


class DatadogMetrics(object):
    def __init__(self, api_key, app_key, flush_interval=10):
        datadog.initialize(api_key=api_key, app_key=app_key)
        self._client = ThreadStats()
        self._flush_interval = flush_interval

        self._host = get_hostname()

    def start(self):
        self._client.start(flush_interval=self._flush_interval,
                           roll_up_interval=self._flush_interval)

    def increment(self, name, count=1, **kwargs):
        self._client.increment(name, count, host=self._host, **kwargs)

    def gauge(self, name, count, **kwargs):
        self._client.gauge(name, count, host=self._host, **kwargs)

    def timing(self, name, duration, **kwargs):
        self._client.timing(name, value=duration, host=self._host, **kwargs)
