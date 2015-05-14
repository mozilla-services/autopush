"""autopush daemon script"""
import sys

import configargparse
import cyclone.web
from autobahn.twisted.websocket import WebSocketServerFactory, listenWS
from twisted.internet import reactor, task
from twisted.python import log

from autopush.endpoint import (EndpointHandler, RegistrationHandler)
from autopush.health import (HealthHandler, StatusHandler)
from autopush.logging import setup_logging
from autopush.settings import AutopushSettings
from autopush.ssl import AutopushSSLContextFactory
from autopush.utils import str2bool
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


def add_shared_args(parser):
    parser.add_argument('--config-shared',
                        help="Common configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('--debug', help='Debug Info.', type=bool,
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
    parser.add_argument('--resolve_hostname',
                        help="Resolve the announced hostname",
                        type=bool, default=False, env_var="RESOLVE_HOSTNAME")
    parser.add_argument('--statsd_host', help="Statsd Host", type=str,
                        default="localhost", env_var="STATSD_HOST")
    parser.add_argument('--statsd_port', help="Statsd Port", type=int,
                        default=8125, env_var="STATSD_PORT")
    parser.add_argument('--ssl_key', help="SSL Key path", type=str,
                        default="", env_var="SSL_KEY")
    parser.add_argument('--ssl_cert', help="SSL Cert path", type=str,
                        default="", env_var="SSL_CERT")
    parser.add_argument('--ssl_dh_param',
                        help="SSL DH Param file (openssl dhparam 1024)",
                        type=str, default="", env_var="SSL_DH_PARAM")
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
    parser.add_argument(
        '--max_data',
        help="Max data segment length in bytes",
        default=4096,
        env_var='MAX_DATA')


def add_bridge_args(parser):
    # GCM
    parser.add_argument('--bridge', help='enable Proprietary Ping',
                        type=bool, default=False, env_var='BRIDGE')
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
    parser.register('type', bool, str2bool)
    parser.add_argument('--config-connection',
                        help="Connection node configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('-p', '--port', help='Websocket Port', type=int,
                        default=8080, env_var="PORT")
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
    parser.add_argument(
        '--min_ping_interval',
        help="Minimum Interval in seconds between pings before " +
        "disconnecting websocket client as being " +
        "'too aggressive'",
        default=20,
        type=int,
        env_var="MIN_PING_INTERVAL")
    parser.add_argument(
        '--auto_ping_interval',
        help="Interval between Websocket pings",
        default=0,
        type=float,
        env_var="AUTO_PING_INTERVAL")
    parser.add_argument(
        '--auto_ping_timeout',
        help="Timeout in seconds for Websocket ping replys",
        default=4,
        type=float,
        env_var="AUTO_PING_TIMEOUT")
    parser.add_argument('--pong_delay', help=("Time to wait after receiving a "
                        "pong for clients that ping too frequently"),
                        default=0, type=int, env_var="PONG_DELAY")

    add_bridge_args(parser)
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
    parser.register('type', bool, str2bool)
    parser.add_argument('--config-endpoint',
                        help="Endpoint node configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('-p', '--port', help='Public HTTP Endpoint Port',
                        type=int, default=8082, env_var="PORT")
    parser.add_argument('--cors', help='Allow CORS PUTs for update.',
                        type=bool, default=False, env_var='ALLOW_CORS')
    add_shared_args(parser)
    add_bridge_args(parser)

    args = parser.parse_args(sysargs)
    return args, parser


def make_settings(args, **kwargs):
    pingConf = None
    if args.bridge:
        pingConf = {}
        # if you have the critical elements for each bridge, create it
        if args.apns_cert_file is not None and args.apns_key_file is not None:
            pingConf["apns"] = {"sandbox": args.apns_sandbox,
                                "cert_file": args.apns_cert_file,
                                "key_file": args.apns_key_file}
        if args.gcm_apikey is not None:
            pingConf["gcm"] = {"ttl": args.gcm_ttl,
                               "dryrun": args.gcm_dryrun,
                               "collapsekey": args.gcm_collapsekey,
                               "apikey": args.gcm_apikey}
        # If you have no settings, you have no bridge.
        if pingConf is {}:
            pingConf = None

    return AutopushSettings(
        crypto_key=args.crypto_key,
        datadog_api_key=args.datadog_api_key,
        datadog_app_key=args.datadog_app_key,
        datadog_flush_interval=args.datadog_flush_interval,
        hostname=args.hostname,
        statsd_host=args.statsd_host,
        statsd_port=args.statsd_port,
        pingConf=pingConf,
        router_tablename=args.router_tablename,
        storage_tablename=args.storage_tablename,
        storage_read_throughput=args.storage_read_throughput,
        storage_write_throughput=args.storage_write_throughput,
        router_read_throughput=args.router_read_throughput,
        router_write_throughput=args.router_write_throughput,
        resolve_hostname=args.resolve_hostname,
        **kwargs
    )


def skip_request_logging(handler):
    """Ignores request logging"""
    pass


def mount_health_handlers(site, settings):
    status = StatusHandler
    status.ap_settings = settings
    health = HealthHandler
    health.ap_settings = settings
    site.add_handlers(".*$", [
        (r"^/status", status),
        (r"^/health", health),
    ])


def connection_main(sysargs=None):
    args, parser = _parse_connection(sysargs)
    settings = make_settings(
        args,
        port=args.port,
        endpoint_scheme=args.endpoint_scheme,
        endpoint_hostname=args.endpoint_hostname,
        endpoint_port=args.endpoint_port,
        router_scheme="https" if args.router_ssl_key else "http",
        router_hostname=args.router_hostname,
        router_port=args.router_port,
        min_ping_interval=args.min_ping_interval,
        auto_ping_interval=args.auto_ping_interval,
        auto_ping_timeout=args.auto_ping_timeout,
        pong_delay=args.pong_delay,
    )
    setup_logging("Autopush")

    r = RouterHandler
    r.ap_settings = settings
    n = NotificationHandler
    n.ap_settings = settings

    # Internal HTTP notification router
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", r),
        (r"/notif/([^\/]+)", n),
    ],
        default_host=settings.router_hostname, debug=args.debug,
        log_function=skip_request_logging
    )
    mount_health_handlers(site, settings)

    # Public websocket server
    proto = "wss" if args.ssl_key else "ws"
    factory = WebSocketServerFactory(
        "%s://%s:%s/" % (proto, args.hostname, args.port),
        debug=args.debug,
        debugCodePaths=args.debug,
    )
    factory.protocol = SimplePushServerProtocol
    factory.protocol.ap_settings = settings
    factory.setProtocolOptions(
        webStatus=False,
        maxFramePayloadSize=2048,
        maxMessagePayloadSize=2048,
        openHandshakeTimeout=5,
    )

    settings.metrics.start()

    # Start the WebSocket listener.
    if args.ssl_key:
        contextFactory = AutopushSSLContextFactory(args.ssl_key,
                                                   args.ssl_cert)
        if args.ssl_dh_param:
            contextFactory.getContext().load_tmp_dh(args.ssl_dh_param)
        listenWS(factory, contextFactory)
    else:
        reactor.listenTCP(args.port, factory)

    # Start the internal routing listener.
    if args.router_ssl_key:
        contextFactory = AutopushSSLContextFactory(args.router_ssl_key,
                                                   args.router_ssl_cert)
        if args.ssl_dh_param:
            contextFactory.getContext().load_tmp_dh(args.ssl_dh_param)
        reactor.listenSSL(args.router_port, site, contextFactory)
    else:
        reactor.listenTCP(args.router_port, site)

    reactor.suggestThreadPoolSize(50)

    l = task.LoopingCall(periodic_reporter, settings)
    l.start(1.0)
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

    # Endpoint HTTP router
    endpoint = EndpointHandler
    endpoint.ap_settings = settings
    register = RegistrationHandler
    register.ap_settings = settings
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", endpoint),
        # PUT /register/ => connect info
        # GET /register/uaid => chid + endpoint
        (r"/register/([^\/]+)?", register),
    ],
        default_host=settings.hostname, debug=args.debug,
        log_function=skip_request_logging
    )
    mount_health_handlers(site, settings)

    # No reason that the endpoint couldn't handle both...
    endpoint.bridge = settings.bridge
    register.bridge = settings.bridge

    settings.metrics.start()

    if args.ssl_key:
        contextFactory = AutopushSSLContextFactory(args.ssl_key,
                                                   args.ssl_cert)
        if args.ssl_dh_param:
            contextFactory.getContext().load_tmp_dh(args.ssl_dh_param)
        reactor.listenSSL(args.port, site, contextFactory)
    else:
        reactor.listenTCP(args.port, site)

    reactor.suggestThreadPoolSize(50)
    reactor.run()
