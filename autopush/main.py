"""autopush/autoendpoint daemon scripts"""
import configargparse
import cyclone.web
from autobahn.twisted.websocket import WebSocketServerFactory, listenWS
from twisted.internet import reactor, task

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
    """Add's a large common set of shared arguments"""
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
    parser.add_argument('--max_data', help="Max data segment length in bytes",
                        default=4096, env_var='MAX_DATA')


def add_external_router_args(parser):
    """Parses out external router arguments"""
    # GCM
    parser.add_argument('--external_router', help='enable external routers',
                        type=bool, default=False, env_var='EXTERNAL_ROUTER')
    label = "GCM Router:"
    parser.add_argument('--gcm_ttl', help="%s Time to Live" % label,
                        type=int, default=60, env_var="GCM_TTL")
    parser.add_argument('--gcm_dryrun',
                        help="%s Dry run (no message sent)" % label,
                        type=bool, default=False, env_var="GCM_DRYRUN")
    parser.add_argument('--gcm_collapsekey',
                        help="%s string to collapse messages" % label,
                        type=str, default="simpleplush",
                        env_var="GCM_COLLAPSEKEY")
    parser.add_argument('--gcm_apikey', help="%s API Key" % label,
                        type=str, env_var="GCM_APIKEY")
    # Apple Push Notification system (APNs) for iOS
    label = "APNS Router:"
    parser.add_argument('--apns_sandbox', help="%s Use Dev Sandbox" % label,
                        type=bool, default=True, env_var="APNS_SANDBOX")
    parser.add_argument('--apns_cert_file',
                        help="%s Certificate PEM file" % label,
                        type=str, env_var="APNS_CERT_FILE")
    parser.add_argument('--apns_key_file', help="%s Key PEM file" % label,
                        type=str, env_var="APNS_KEY_FILE")
    # UDP
    parser.add_argument('--udp_timeout',
        help="UDP: idle timeout before closing socket",
        type=int, default=0,
        env_var="UDP_TIMEOUT")
    parser.add_argument(
        '--udp_pem',
        help="UDP: custom TLS PEM file for remote Wake server",
        type=str, env_var="UDP_PEM")

def _parse_connection(sysargs):
    """Parse out connection node arguments for an autopush node"""
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
    parser.add_argument('--auto_ping_interval',
                        help="Interval between Websocket pings", default=0,
                        type=float, env_var="AUTO_PING_INTERVAL")
    parser.add_argument('--auto_ping_timeout',
                        help="Timeout in seconds for Websocket ping replys",
                        default=4, type=float, env_var="AUTO_PING_TIMEOUT")
    parser.add_argument('--max_connections',
                        help="The maximum number of concurrent connections.",
                        default=0, type=int, env_var="MAX_CONNECTIONS")

    add_external_router_args(parser)
    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def _parse_endpoint(sysargs):
    """Parses out endpoint arguments for an autoendpoint node"""
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
    add_external_router_args(parser)

    args = parser.parse_args(sysargs)
    return args, parser


def make_settings(args, **kwargs):
    """Helper function to make a :class:`AutopushSettings` object"""
    router_conf = {}
    # Some routers require a websocket to timeout on idle (e.g. UDP)
    timeout = 0
    if args.external_router:
        # if you have the critical elements for each external router, create it
        if args.apns_cert_file is not None and args.apns_key_file is not None:
            router_conf["apns"] = {"sandbox": args.apns_sandbox,
                                   "cert_file": args.apns_cert_file,
                                   "key_file": args.apns_key_file}
        if args.gcm_apikey is not None:
            router_conf["gcm"] = {"ttl": args.gcm_ttl,
                                  "dryrun": args.gcm_dryrun,
                                  "collapsekey": args.gcm_collapsekey,
                                  "apikey": args.gcm_apikey}
        if args.udp_pem is not None and args.udp_timeout is not 0:
            timeout = args.udp_timeout
            router_conf["udp"] = {"idle": args.udp_timeout,
                                  "cert": args.udp_pem}

    return AutopushSettings(
        crypto_key=args.crypto_key,
        datadog_api_key=args.datadog_api_key,
        datadog_app_key=args.datadog_app_key,
        datadog_flush_interval=args.datadog_flush_interval,
        hostname=args.hostname,
        statsd_host=args.statsd_host,
        statsd_port=args.statsd_port,
        router_conf=router_conf,
        router_tablename=args.router_tablename,
        storage_tablename=args.storage_tablename,
        storage_read_throughput=args.storage_read_throughput,
        storage_write_throughput=args.storage_write_throughput,
        router_read_throughput=args.router_read_throughput,
        router_write_throughput=args.router_write_throughput,
        resolve_hostname=args.resolve_hostname,
        idle_timeout=timeout,
        **kwargs
    )


def skip_request_logging(handler):
    """Ignores request logging"""
    pass


def mount_health_handlers(site, settings):
    """Create a health check HTTP handler on a cyclone site object"""
    status = StatusHandler
    status.ap_settings = settings
    health = HealthHandler
    health.ap_settings = settings
    site.add_handlers(".*$", [
        (r"^/status", status),
        (r"^/health", health),
    ])


def connection_main(sysargs=None):
    """Main entry point to setup a connection node, aka the autopush script"""
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
    )
    setup_logging("Autopush")

    r = RouterHandler
    r.ap_settings = settings
    n = NotificationHandler
    n.ap_settings = settings

    # Internal HTTP notification router
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", r),
        (r"/notif/([^\/]+)(/([^\/]+))?", n),
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
        autoPingInterval=args.auto_ping_interval,
        autoPingTimeout=args.auto_ping_timeout,
        maxConnections=args.max_connections
    )
    settings.factory = factory

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
    reactor.run()


def endpoint_main(sysargs=None):
    """Main entry point to setup an endpoint node, aka the autoendpoint
    script"""
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
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", EndpointHandler, dict(ap_settings=settings)),
        # PUT /register/ => connect info
        # GET /register/uaid => chid + endpoint
        (r"/register(?:/(.+))?", RegistrationHandler,
         dict(ap_settings=settings)),
    ],
        default_host=settings.hostname, debug=args.debug,
        log_function=skip_request_logging
    )
    mount_health_handlers(site, settings)

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
