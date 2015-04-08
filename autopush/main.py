"""autopush daemon script"""
import sys

import configargparse
import cyclone.web
from autobahn.twisted.websocket import WebSocketServerFactory, listenWS
from twisted.internet import reactor, task, ssl
from twisted.python import log

from autopush.endpoint import (EndpointHandler, RegistrationHandler)
from autopush.health import StatusHandler
from autopush.logging import setup_logging
from autopush.settings import AutopushSettings
from autopush.websocket import (
    SimplePushServerProtocol,
    RouterHandler,
    NotificationHandler,
    periodic_reporter
)


shared_config_files = [
    '/etc/autopush_shared.ini',
    '~/.autopush_shared.ini',
    '.autopush_shared.ini',
]


def add_ssl_args(parser):
    parser.add_argument('--ssl_key', help="SSL Key path", type=str,
                        default="", env_var="SSL_KEY")
    parser.add_argument('--ssl_cert', help="SSL Cert path", type=str,
                        default="", env_var="SSL_CERT")


def add_shared_args(parser):
    parser.add_argument('--debug', help='Debug Info.', action='store_true',
                        default=False, env_var="DEBUG")
    parser.add_argument('--crypto_key', help="Crypto key for tokens", type=str,
                        default="i_CYcNKa2YXrF_7V1Y-2MFfoEl7b6KX55y_9uvOKfJQ=",
                        env_var="CRYPTO_KEY")
    parser.add_argument('--datadog_api_key', help="DataDog API Key", type=str,
                        default="", env_var="DATADOG_API_KEY")
    parser.add_argument('--datadog_app_key', help="DataDog App Key", type=str,
                        default="", env_var="DATADOG_APP_KEY")
    parser.add_argument('--datadog_flush_interval',
                        help="DataDog Flush Interval", type=int,
                        default=10, env_var="DATADOG_FLUSH_INTERVAL")
    parser.add_argument('--hostname', help="Hostname to announce under",
                        type=str, default=None, env_var="HOSTNAME")
    parser.add_argument('--statsd_host', help="Statsd Host", type=str,
                        default="localhost", env_var="STATSD_HOST")
    parser.add_argument('--statsd_port', help="Statsd Port", type=int,
                        default=8125, env_var="STATSD_PORT")
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
    parser.add_argument('--log_level', type=int, default=40,
                        env_var="LOG_LEVEL")


def add_connection_args(parser):
    parser.add_argument('--router_hostname',
                        help="HTTP Router Hostname to use for internal "
                        "router connects", type=str, default=None,
                        env_var="ROUTER_HOSTNAME")
    parser.add_argument('-r', '--router_port',
                        help="HTTP Router Port for internal router connects",
                        type=int, default=8081, env_var="ROUTER_PORT")
    parser.add_argument('--router_ssl_key',
                        help="Routing listener SSL key path", type=str,
                        default="", env_var="ROUTER_SSL_KEY")
    parser.add_argument('--router_ssl_cert',
                        help="Routing listener SSL cert path", type=str,
                        default="", env_var="ROUTER_SSL_CERT")
    parser.add_argument('--endpoint_scheme', help="HTTP Endpoint Scheme",
                        type=str, default="http", env_var="ENDPOINT_SCHEME")
    parser.add_argument('--endpoint_hostname', help="HTTP Endpoint Hostname",
                        type=str, default=None, env_var="ENDPOINT_HOSTNAME")
    parser.add_argument('-e', '--endpoint_port', help="HTTP Endpoint Port",
                        type=int, default=8082, env_var="ENDPOINT_PORT")


def add_endpoint_args(parser):
    parser.add_argument('--cors', help='Allow CORS PUTs for update.',
                        action='store_true', default=False,
                        env_var='ALLOW_CORS')


def add_pinger_args(parser):
    # GCM
    parser.add_argument('--pinger', help='enable Proprietary Ping',
                        action='store_true',
                        default=False, env_var='PINGER')
    label = "Proprietary Ping: Google Cloud Messaging:"
    parser.add_argument('--gcm_ttl',
                        help="%s Time to Live" % label,
                        type=int, default=60, env_var="GCM_TTL")
    parser.add_argument('--gcm_dryrun',
                        help="%s Dry run (no message sent)" % label,
                        type=bool, default=False, env_var="GCM_DRYRUN")
    parser.add_argument('--gcm_collapsekey',
                        help="%s string to collapse messages" % label,
                        type=str, default="simpleplush",
                        env_var="GCM_COLLAPSEKEY")
    parser.add_argument('--gcm_apikey',
                        help="%s API Key" % label,
                        type=str, env_var="GCM_APIKEY")
    # Apple Push Notification system (APNs) for iOS
    label = "Proprietary Ping: Apple Push Notification System:"
    parser.add_argument('--apns_sandbox',
                        help="%s Use Dev Sandbox",
                        type=bool, default=True, env_var="APNS_SANDBOX")
    parser.add_argument('--apns_cert_file',
                        help="%s Certificate PEM file" % label,
                        type=str, env_var="APNS_CERT_FILE")
    parser.add_argument('--apns_key_file',
                        help="%s Key PEM file",
                        type=str, env_var="APNS_KEY_FILE")


def _parse_connection(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    config_files = [
        '/etc/autopush_connection.ini',
        '~/.autopush_connection.ini',
        '.autopush_connection.ini'
    ]
    parser = configargparse.ArgumentParser(
        description='Runs a Connection Node.',
        default_config_files=shared_config_files + config_files)
    parser.add_argument('--config-shared',
                        help="Common configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('--config-connection',
                        help="Connection node configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('-p', '--port', help='Websocket Port', type=int,
                        default=8080, env_var="PORT")
    add_connection_args(parser)
    add_pinger_args(parser)
    add_ssl_args(parser)
    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def _parse_endpoint(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    config_files = [
        '/etc/autopush_endpoint.ini',
        '~/.autopush_endpoint.ini',
        '.autopush_endpoint.ini'
    ]
    parser = configargparse.ArgumentParser(
        description='Runs an Endpoint Node.',
        default_config_files=shared_config_files + config_files)
    parser.add_argument('--config-shared',
                        help="Common configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('--config-endpoint',
                        help="Endpoint node configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('-p', '--port', help='Public HTTP Endpoint Port',
                        type=int, default=8082, env_var="PORT")
    add_endpoint_args(parser)
    add_pinger_args(parser)
    add_ssl_args(parser)
    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def make_settings(args, **kwargs):
    pingConf = None
    if args.pinger:
        pingConf = {}
        # if you have the critical elements for each pinger, create it
        if args.apns_cert_file is not None and args.apns_key_file is not None:
            pingConf["apns"] = {"sandbox": args.apns_sandbox,
                                "cert_file": args.apns_cert_file,
                                "key_file": args.apns_key_file}
        if args.gcm_apikey is not None:
            pingConf["gcm"] = {"ttl": args.gcm_ttl,
                               "dryrun": args.gcm_dryrun,
                               "collapsekey": args.gcm_collapsekey,
                               "apikey": args.gcm_apikey}
        # If you have no settings, you have no pinger.
        if pingConf is {}:
            pingConf = None

    return AutopushSettings(
        crypto_key=args.crypto_key,
        datadog_api_key=args.datadog_api_key,
        datadog_app_key=args.datadog_app_key,
        datadog_flush_interval=args.datadog_flush_interval,
        statsd_host=args.statsd_host,
        statsd_port=args.statsd_port,
        pingConf=pingConf,
        router_tablename=args.router_tablename,
        storage_tablename=args.storage_tablename,
        storage_read_throughput=args.storage_read_throughput,
        storage_write_throughput=args.storage_write_throughput,
        router_read_throughput=args.router_read_throughput,
        router_write_throughput=args.router_write_throughput,
        **kwargs
    )


def skip_request_logging(handler):
    """Ignores request logging"""
    pass


def _setup_connection(settings, origin, debug=False, wsContextFactory=None,
                      routerContextFactory=None):
    r = RouterHandler
    r.ap_settings = settings
    n = NotificationHandler
    n.ap_settings = settings
    s = StatusHandler
    s.ap_settings = settings

    # Internal HTTP notification router
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", r),
        (r"/notif/([^\/]+)", n),
        (r"^/status/", s),
    ],
        default_host=settings.router_hostname, debug=debug,
        log_function=skip_request_logging
    )

    # Public websocket server
    factory = WebSocketServerFactory(
        origin,
        debug=debug,
        debugCodePaths=debug,
    )
    factory.protocol = SimplePushServerProtocol
    factory.protocol.ap_settings = settings
    factory.setProtocolOptions(
        webStatus=False,
        maxFramePayloadSize=2048,
        maxMessagePayloadSize=2048,
        openHandshakeTimeout=5,
        failByDrop=False,
    )

    # Start the WebSocket listener.
    if wsContextFactory:
        listenWS(factory, wsContextFactory)
    else:
        reactor.listenTCP(settings.connection_port, factory)

    # Start the internal routing listener.
    if routerContextFactory:
        reactor.listenSSL(settings.router_port, site, routerContextFactory)
    else:
        reactor.listenTCP(settings.router_port, site)

    l = task.LoopingCall(periodic_reporter, settings)
    l.start(1.0)


def _setup_endpoint(settings, debug=False, contextFactory=None):
    # Endpoint HTTP router
    endpoint = EndpointHandler
    endpoint.ap_settings = settings
    register = RegistrationHandler
    register.ap_settings = settings
    status = StatusHandler
    status.ap_settings = settings
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", endpoint),
        # PUT /register/ => connect info
        # GET /register/uaid => chid + endpoint
        (r"/register/([^\/]+)?", register),
        (r"^/status", status),
    ],
        default_host=settings.endpoint_hostname, debug=debug,
        log_function=skip_request_logging
    )

    # No reason that the endpoint couldn't handle both...
    endpoint.pinger = settings.pinger
    register.pinger = settings.pinger

    if contextFactory:
        reactor.listenSSL(settings.endpoint_port, site, contextFactory)
    else:
        reactor.listenTCP(settings.endpoint_port, site)


def connection_main(sysargs=None):
    args, parser = _parse_connection(sysargs)
    settings = make_settings(
        args,
        endpoint_scheme=args.endpoint_scheme,
        endpoint_hostname=args.endpoint_hostname,
        connection_hostname=args.hostname,
        connection_port=args.port,
        endpoint_port=args.endpoint_port,
        router_scheme="https" if args.router_ssl_key else "http",
        router_hostname=args.router_hostname,
        router_port=args.router_port,
    )
    setup_logging("Autopush")

    proto = "wss" if args.ssl_key else "ws"
    origin = "%s://%s:%s/" % (proto, settings.connection_hostname,
                              settings.connection_port)

    wsContextFactory = None
    if args.ssl_key:
        wsContextFactory = ssl.DefaultOpenSSLContextFactory(args.ssl_key,
                                                            args.ssl_cert)

    routerContextFactory = None
    if args.router_ssl_key:
        routerContextFactory = ssl.DefaultOpenSSLContextFactory(
            args.router_ssl_key, args.router_ssl_cert)

    settings.metrics.start()
    _setup_connection(settings, origin, debug=args.debug,
                      wsContextFactory=wsContextFactory,
                      routerContextFactory=routerContextFactory)

    reactor.suggestThreadPoolSize(50)

    try:
        reactor.run()
    except KeyboardInterrupt:
        log.debug('Bye')


def endpoint_main(sysargs=None):
    args, parser = _parse_endpoint(sysargs)
    settings = make_settings(
        args,
        endpoint_scheme="https" if args.ssl_key else "http",
        endpoint_hostname=args.hostname,
        endpoint_port=args.port,
        enable_cors=args.cors
    )

    setup_logging("Autoendpoint")

    contextFactory = None
    if args.ssl_key:
        contextFactory = ssl.DefaultOpenSSLContextFactory(args.ssl_key,
                                                          args.ssl_cert)

    settings.metrics.start()
    _setup_endpoint(settings, debug=args.debug, contextFactory=contextFactory)

    reactor.suggestThreadPoolSize(50)
    reactor.run()


def unified_main(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = configargparse.ArgumentParser(
        description='Runs a unified push server.',
        default_config_files=[
            '/etc/autopush.ini',
            '~/.autopush.ini',
            '.autopush.ini'
        ])
    parser.add_argument('-c', '--connection_port', help="Websocket Port",
                        type=int, default=8080, env_var="CONNECTION_PORT")
    parser.add_argument('--connection_ssl_key',
                        help="Connection node SSL key path",
                        type=str, default="", env_var="CONNECTION_SSL_KEY")
    parser.add_argument('--connection_ssl_cert',
                        help="Connection node SSL cert path",
                        type=str, default="", env_var="CONNECTION_SSL_CERT")
    parser.add_argument('--endpoint_ssl_key',
                        help="Endpoint node SSL key path",
                        type=str, default="", env_var="ENDPOINT_SSL_KEY")
    parser.add_argument('--endpoint_ssl_cert',
                        help="Endpoint node SSL cert path",
                        type=str, default="", env_var="ENDPOINT_SSL_CERT")
    add_connection_args(parser)
    add_endpoint_args(parser)
    add_pinger_args(parser)
    add_shared_args(parser)

    args = parser.parse_args(sysargs)
    settings = make_settings(
        args,
        endpoint_scheme="https" if args.endpoint_ssl_key else "http",
        endpoint_hostname=args.hostname,
        connection_hostname=args.hostname,
        connection_port=args.connection_port,
        endpoint_port=args.endpoint_port,
        router_scheme="https" if args.router_ssl_key else "http",
        router_hostname=args.router_hostname,
        router_port=args.router_port,
        enable_cors=args.cors
    )
    setup_logging("Autonode")

    proto = "wss" if args.connection_ssl_cert else "ws"
    origin = "%s://%s:%s/" % (proto, settings.connection_hostname,
                              settings.connection_port)

    wsContextFactory = routerContextFactory = endpointContextFactory = None
    if args.connection_ssl_cert:
        wsContextFactory = ssl.DefaultOpenSSLContextFactory(
            args.connection_ssl_cert, args.connection_ssl_key)

    if args.router_ssl_cert:
        routerContextFactory = ssl.DefaultOpenSSLContextFactory(
            args.router_ssl_cert, args.router_ssl_key)

    if args.endpoint_ssl_cert:
        endpointContextFactory = ssl.DefaultOpenSSLContextFactory(
            args.endpoint_ssl_cert, args.endpoint_ssl_key)

    settings.metrics.start()
    _setup_connection(settings, origin, debug=args.debug,
                      wsContextFactory=wsContextFactory,
                      routerContextFactory=routerContextFactory)
    _setup_endpoint(settings, debug=args.debug,
                    contextFactory=endpointContextFactory)

    reactor.suggestThreadPoolSize(50)
    reactor.run()
