"""autopush daemon script"""
import sys
import argparse

import cyclone.web
from autobahn.twisted.websocket import WebSocketServerFactory
from pyramid.config import Configurator
from twisted.python import log
from twisted.internet import reactor
from wsgiref.simple_server import make_server

from autopush.websocket import SimplePushServerProtocol, RouterHandler
from autopush.settings import AutopushSettings
from autopush.endpoint import endpoint


def _parse(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Runs a Loads broker.')
    parser.add_argument('-p', '--port', help='HTTP Port', type=int,
                        default=8080)
    parser.add_argument('-r', '--router_port', help="HTTP Router Port",
                        type=int, default=8081)
    parser.add_argument('-e', '--endpoint_port', help="HTTP Endpoint Port",
                        type=int, default=8082)
    parser.add_argument('--debug', help='Debug Info.', action='store_true',
                        default=False)
    parser.add_argument('--crypto_key', help="Crypto key for tokens", type=str,
                        default="i_CYcNKa2YXrF_7V1Y-2MFfoEl7b6KX55y_9uvOKfJQ=")
    parser.add_argument('--influx-password', help='InfluxDB password',
                        type=str, default='root')
    parser.add_argument('--influx-secure', help='Use TLS for InfluxDB',
                        action='store_true', default=False)
    parser.add_argument('--initial-db', help="JSON file to initialize the db.",
                        type=str, default='pushgo.json')

    args = parser.parse_args(sysargs)
    return args, parser


def _parse_endpoint(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Runs a Loads broker.')
    parser.add_argument('-p', '--port', help='HTTP Endpoint Port', type=int,
                        default=8082)
    parser.add_argument('--debug', help='Debug Info.', action='store_true',
                        default=True)
    parser.add_argument('--crypto_key', help="Crypto key for tokens", type=str,
                        default="i_CYcNKa2YXrF_7V1Y-2MFfoEl7b6KX55y_9uvOKfJQ=")
    args = parser.parse_args(sysargs)
    return args, parser


def connection_main(sysargs=None):
    args, parser = _parse(sysargs)
    settings = AutopushSettings()
    settings.update(crypto_key=args.crypto_key)

    if args.debug:
        log.startLogging(sys.stdout)

    r = RouterHandler
    r.settings = settings

    site = cyclone.web.Application([
        (r"/push/([^\/]+)", r)
    ])

    factory = WebSocketServerFactory("ws://localhost:%s/" % args.port,
                                     debug=args.debug)
    factory.protocol = SimplePushServerProtocol
    factory.protocol.settings = settings
    settings.ws_port = args.port
    settings.router_port = args.router_port
    settings.endpoint_port = args.endpoint_port

    reactor.listenTCP(args.port, factory)
    reactor.listenTCP(args.router_port, site)
    try:
        reactor.run()
    except KeyboardInterrupt:
        log.debug('Bye')


def endpoint_main(sysargs=None):
    args, parser = _parse_endpoint(sysargs)
    settings = AutopushSettings()
    settings.update(crypto_key=args.crypto_key)

    config = Configurator()
    config.registry.app_settings = settings
    config.add_route('push', '/push/{token}')
    config.add_view(endpoint, route_name='push')
    app = config.make_wsgi_app()
    print "Serving on %s:%s" % (settings.hostname, args.port)
    server = make_server(settings.hostname, args.port, app)
    server.serve_forever()
