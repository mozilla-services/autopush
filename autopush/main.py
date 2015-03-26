"""autopush daemon script"""
import os
import sys

import configargparse
import cyclone.web
import raven
import twisted.python
from autobahn.twisted.websocket import WebSocketServerFactory, listenWS
from functools import partial
from twisted.python import log
from twisted.internet import reactor, task, ssl
from txstatsd.client import StatsDClientProtocol

from autopush.endpoint import EndpointHandler
from autopush.settings import AutopushSettings
from autopush.websocket import (
    SimplePushServerProtocol,
    RouterHandler,
    NotificationHandler,
    periodic_reporter
)


def add_shared_args(parser):
    parser.add_argument('--debug', help='Debug Info.', action='store_true',
                        default=False, env_var="DEBUG")
    parser.add_argument('--crypto_key', help="Crypto key for tokens", type=str,
                        default="i_CYcNKa2YXrF_7V1Y-2MFfoEl7b6KX55y_9uvOKfJQ=",
                        env_var="CRYPTO_KEY")
    parser.add_argument('--hostname', help="Hostname to announce under",
                        type=str, default=None, env_var="HOSTNAME")
    parser.add_argument('--statsd_host', help="Statsd Host", type=str,
                        default="localhost", env_var="STATSD_HOST")
    parser.add_argument('--statsd_port', help="Statsd Port", type=int,
                        default=8125, env_var="STATSD_PORT")
    parser.add_argument('--ssl_key', help="SSL Key path", type=str,
                        default="", env_var="SSL_KEY")
    parser.add_argument('--ssl_cert', help="SSL Cert path", type=str,
                        default="", env_var="SSL_CERT")
    parser.add_argument('--router_tablename', help="DynamoDB Router Tablename",
                        type=str, default="router", env_var="ROUTER_TABLENAME")
    parser.add_argument('--storage_tablename',
                        help="DynamoDB Storage Tablename", type=str,
                        default="storage", env_var="STORAGE_TABLENAME")
    parser.add_argument('--storage_read_throughput',
                        help="DynamoDB storage read throughput",
                        type=int, default=5, env_var="STORAGE_READ_THROUGHPUT")
    parser.add_argument('--storage_write_throughput',
                        help="DynamoDB storage write throughput",
                        type=int, default=5,
                        env_var="STORAGE_WRITE_THROUGHPUT")
    parser.add_argument('--router_read_throughput',
                        help="DynamoDB router read throughput",
                        type=int, default=5, env_var="ROUTER_READ_THROUGHPUT")
    parser.add_argument('--router_write_throughput',
                        help="DynamoDB router write throughput",
                        type=int, default=5, env_var="ROUTER_WRITE_THROUGHPUT")


def _parse_connection(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = configargparse.ArgumentParser(
        description='Runs a Connection Node.')
    parser.add_argument('-p', '--port', help='Websocket Port', type=int,
                        default=8080, env_var="PORT")
    parser.add_argument('--router_hostname',
                        help="HTTP Rotuer Hostname to use for internal "
                        "router connects", type=str, default=None,
                        env_var="ROUTER_HOSTNAME")
    parser.add_argument('-r', '--router_port',
                        help="HTTP Router Port for internal router connects",
                        type=int, default=8081, env_var="ROUTER_PORT")
    parser.add_argument('--endpoint_hostname', help="HTTP Endpoint Hostname",
                        type=str, default=None, env_var="ENDPOINT_HOSTNAME")
    parser.add_argument('-e', '--endpoint_port', help="HTTP Endpoint Port",
                        type=int, default=8082, env_var="ENDPOINT_PORT")

    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def _parse_endpoint(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = configargparse.ArgumentParser(
        description='Runs an Endpoint Node.')
    parser.add_argument('-p', '--port', help='Public HTTP Endpoint Port',
                        type=int, default=8082, env_var="PORT")
    parser.add_argument('--cors', help='Allow CORS PUTs for update.',
                        action='store_true', default=False,
                        env_var='ALLOW_CORS')
    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def make_settings(args, **kwargs):
    return AutopushSettings(
        crypto_key=args.crypto_key,
        hostname=args.hostname,
        statsd_host=args.statsd_host,
        statsd_port=args.statsd_port,
        router_tablename=args.router_tablename,
        storage_tablename=args.storage_tablename,
        storage_read_throughput=args.storage_read_throughput,
        storage_write_throughput=args.storage_write_throughput,
        router_read_throughput=args.router_read_throughput,
        router_write_throughput=args.router_write_throughput,
        **kwargs
    )


def logToSentry(client, event):
    if not event.get('isError') or 'failure' not in event:
        return

    f = event['failure']
    client.captureException((f.type, f.value, f.getTracebackObject()))


def unified_setup():
    if 'SENTRY_DSN' in os.environ:
        # Setup the Sentry client
        client = raven.Client(release=raven.fetch_package_version())
        logger = partial(logToSentry, client)
        twisted.python.log.addObserver(logger)


def connection_main(sysargs=None):
    args, parser = _parse_connection(sysargs)
    settings = make_settings(
        args,
        port=args.port,
        endpoint_hostname=args.endpoint_hostname,
        endpoint_port=args.endpoint_port,
        router_hostname=args.router_hostname,
        router_port=args.router_port,
    )

    log.startLogging(sys.stdout)
    unified_setup()

    r = RouterHandler
    r.settings = settings
    n = NotificationHandler
    n.settings = settings

    # Internal HTTP notification router
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", r),
        (r"/notif/([^\/]+)", n)
    ], default_host=settings.router_hostname)

    # Public websocket server
    proto = "wss" if args.ssl_key else "ws"
    factory = WebSocketServerFactory(
        "%s://%s:%s/" % (proto, args.hostname, args.port),
        debug=args.debug,
        debugCodePaths=args.debug,
    )
    factory.protocol = SimplePushServerProtocol
    factory.protocol.settings = settings
    factory.setProtocolOptions(
        webStatus=False,
        maxFramePayloadSize=2048,
        maxMessagePayloadSize=2048,
        openHandshakeTimeout=5,
        failByDrop=False,
    )

    protocol = StatsDClientProtocol(settings.metrics_client)

    if args.ssl_key:
        contextFactory = ssl.DefaultOpenSSLContextFactory(args.ssl_key,
                                                          args.ssl_cert)
        listenWS(factory, contextFactory)
        reactor.listenSSL(args.router_port, site, contextFactory)
    else:
        reactor.listenTCP(args.port, factory)
        reactor.listenTCP(args.router_port, site)

    reactor.listenUDP(0, protocol)
    reactor.suggestThreadPoolSize(50)

    l = task.LoopingCall(periodic_reporter, settings)
    l.start(1.0)
    try:
        reactor.run()
    except KeyboardInterrupt:
        log.debug('Bye')


def endpoint_main(sysargs=None):
    args, parser = _parse_endpoint(sysargs)
    settings = make_settings(args, enable_cors=args.cors)

    log.startLogging(sys.stdout)

    unified_setup()

    # Endpoint HTTP router
    endpoint = EndpointHandler
    endpoint.ap_settings = settings
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", endpoint)
    ], default_host=settings.hostname, debug=args.debug
    )

    protocol = StatsDClientProtocol(settings.metrics_client)

    if args.ssl_key:
        contextFactory = ssl.DefaultOpenSSLContextFactory(args.ssl_key,
                                                          args.ssl_cert)
        reactor.listenSSL(args.port, site, contextFactory)
    else:
        reactor.listenTCP(args.port, site)

    reactor.listenUDP(0, protocol)
    reactor.suggestThreadPoolSize(50)
    reactor.run()
