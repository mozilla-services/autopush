"""autopush daemon script"""
import sys
import argparse

import cyclone.web
from autobahn.twisted.websocket import WebSocketServerFactory
from boto.dynamodb2.exceptions import ProvisionedThroughputExceededException
from pyramid.config import Configurator
from twisted.python import log
from twisted.internet import reactor
from waitress import serve

from autopush.websocket import (
    SimplePushServerProtocol,
    RouterHandler,
    NotificationHandler,
    periodic_reporter
)
from autopush.settings import AutopushSettings
from autopush.endpoint import (
    endpoint,
    provision_exceeded,
)


def add_shared_args(parser):
    parser.add_argument('--debug', help='Debug Info.', action='store_true',
                        default=False)
    parser.add_argument('--crypto_key', help="Crypto key for tokens", type=str,
                        default="i_CYcNKa2YXrF_7V1Y-2MFfoEl7b6KX55y_9uvOKfJQ=")
    parser.add_argument('--hostname', help="Hostname to announce under",
                        type=str, default=None)
    parser.add_argument('--statsd_host', help="Statsd Host", type=str,
                        default="localhost")
    parser.add_argument('--statsd_port', help="Statsd Port", type=int,
                        default=8125)


def _parse_connection(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Runs a Connection Node.')
    parser.add_argument('-p', '--port', help='Websocket Port', type=int,
                        default=8080)
    parser.add_argument('--router_hostname',
                        help="HTTP Rotuer Hostname to use for internal "
                        "router connects", type=str, default=None)
    parser.add_argument('-r', '--router_port',
                        help="HTTP Router Port for internal router connects",
                        type=int, default=8081)
    parser.add_argument('--endpoint_hostname', help="HTTP Endpoint Hostname",
                        type=str, default=None)
    parser.add_argument('-e', '--endpoint_port', help="HTTP Endpoint Port",
                        type=int, default=8082)

    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def _parse_endpoint(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Runs an Endpoint Node.')
    parser.add_argument('-p', '--port', help='Public HTTP Endpoint Port',
                        type=int, default=8082)

    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def make_settings(args, **kwargs):
    return AutopushSettings(
        crypto_key=args.crypto_key,
        hostname=args.hostname,
        statsd_host=args.statsd_host,
        statsd_port=args.statsd_port,
        **kwargs
    )


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
    factory = WebSocketServerFactory(
        "ws://%s:%s/" % (args.hostname, args.port),
        debug=args.debug
    )
    factory.protocol = SimplePushServerProtocol
    factory.protocol.settings = settings
    factory.setProtocolOptions(allowHixie76=True)

    reactor.listenTCP(args.port, factory)
    reactor.listenTCP(args.router_port, site)
    reactor.suggestThreadPoolSize(50)
    reactor.callLater(1, periodic_reporter, settings)
    try:
        reactor.run()
    except KeyboardInterrupt:
        log.debug('Bye')


def endpoint_main(sysargs=None):
    args, parser = _parse_endpoint(sysargs)
    settings = make_settings(args)

    config = Configurator()
    config.registry.app_settings = settings
    config.add_route('push', '/push/{token}')
    config.add_view(endpoint, route_name='push')
    config.add_view(provision_exceeded,
                    context=ProvisionedThroughputExceededException)
    app = config.make_wsgi_app()
    print "Serving on %s:%s" % (settings.hostname, args.port)
    serve(app, host=settings.hostname, port=args.port, threads=50)
