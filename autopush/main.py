"""autopush/autoendpoint daemon scripts"""
import json
import os

import configargparse
import cyclone.web
from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import WebSocketServerFactory
from twisted.internet import reactor, task
from twisted.logger import Logger
from twisted.web.server import Site

import autopush.db as db
import autopush.utils as utils
from autopush.endpoint import (
    EndpointHandler,
    MessageHandler,
    RegistrationHandler,
)
from autopush.log_check import LogCheckHandler
from autopush.health import (HealthHandler, StatusHandler)
from autopush.logging import PushLogger
from autopush.settings import AutopushSettings
from autopush.ssl import AutopushSSLContextFactory
from autopush.websocket import (
    PushServerProtocol,
    RouterHandler,
    NotificationHandler,
    periodic_reporter,
    DefaultResource,
    StatusResource,
)
from autopush.web.simplepush import SimplePushHandler
from autopush.web.webpush import WebPushHandler
from autopush.web.limitedhttpconnection import LimitedHTTPConnection


shared_config_files = [
    '/etc/autopush_shared.ini',
    'configs/autopush_shared.ini',
    '~/.autopush_shared.ini',
    '.autopush_shared.ini',
]
log = Logger()


def add_shared_args(parser):
    """Add's a large common set of shared arguments"""
    parser.add_argument('--config-shared',
                        help="Common configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('--debug', help='Debug Info.', action="store_true",
                        default=False, env_var="DEBUG")
    parser.add_argument('--log_level', help='Log level to log', type=str,
                        default="", env_var="LOG_LEVEL")
    parser.add_argument('--log_output', help="Log output, stdout or filename",
                        default="stdout", env_var="LOG_OUTPUT")
    parser.add_argument('--firehose_stream_name', help="Firehose Delivery"
                        " Stream Name", default="", env_var="STREAM_NAME",
                        type=str)
    parser.add_argument('--crypto_key', help="Crypto key for tokens",
                        default=[], env_var="CRYPTO_KEY", type=str,
                        action="append")
    parser.add_argument('--key_hash', help="Key to hash IDs for storage",
                        default="", env_var="KEY_HASH", type=str)
    parser.add_argument('--datadog_api_key', help="DataDog API Key", type=str,
                        default="", env_var="DATADOG_API_KEY")
    parser.add_argument('--datadog_app_key', help="DataDog App Key", type=str,
                        default="", env_var="DATADOG_APP_KEY")
    parser.add_argument('--datadog_flush_interval',
                        help="DataDog Flush Interval", type=int,
                        default=10, env_var="DATADOG_FLUSH_INTERVAL")
    parser.add_argument('--hostname', help="Hostname to announce under",
                        type=str, default=None, env_var="LOCAL_HOSTNAME")
    parser.add_argument('--resolve_hostname',
                        help="Resolve the announced hostname",
                        action="store_true", default=False,
                        env_var="RESOLVE_HOSTNAME")
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
    parser.add_argument('--message_tablename',
                        help="DynamoDB Message Tablename", type=str,
                        default="message", env_var="MESSAGE_TABLENAME")
    parser.add_argument('--message_read_throughput',
                        help="DynamoDB message read throughput",
                        type=int, default=5, env_var="MESSAGE_READ_THROUGHPUT")
    parser.add_argument('--message_write_throughput',
                        help="DynamoDB message write throughput",
                        type=int, default=5,
                        env_var="MESSAGE_WRITE_THROUGHPUT")
    parser.add_argument('--router_read_throughput',
                        help="DynamoDB router read throughput",
                        type=int, default=5, env_var="ROUTER_READ_THROUGHPUT")
    parser.add_argument('--router_write_throughput',
                        help="DynamoDB router write throughput",
                        type=int, default=5, env_var="ROUTER_WRITE_THROUGHPUT")
    parser.add_argument('--max_data', help="Max data segment length in bytes",
                        default=4096, env_var='MAX_DATA')
    parser.add_argument('--env',
                        help="The environment autopush is running under",
                        default='development', env_var='AUTOPUSH_ENV')
    parser.add_argument('--endpoint_scheme', help="HTTP Endpoint Scheme",
                        type=str, default="http", env_var="ENDPOINT_SCHEME")
    parser.add_argument('--endpoint_hostname', help="HTTP Endpoint Hostname",
                        type=str, default=None, env_var="ENDPOINT_HOSTNAME")
    parser.add_argument('-e', '--endpoint_port', help="HTTP Endpoint Port",
                        type=int, default=8082, env_var="ENDPOINT_PORT")
    parser.add_argument('--human_logs', help="Enable human readable logs",
                        action="store_true", default=False,
                        env_var="HUMAN_LOGS")
    parser.add_argument('--no_aws', help="Skip AWS meta information checks",
                        action="store_true", default=False)
    # No ENV because this is for humans
    add_external_router_args(parser)
    obsolete_args(parser)


def obsolete_args(parser):
    """ Obsolete and soon to be disabled configuration arguments.

    These are included to prevent startup errors with old config files.

    """
    parser.add_argument('--external_router', help='OBSOLETE')
    parser.add_argument('--max_message_size', type=int, help="OBSOLETE")
    parser.add_argument('--s3_bucket', help='OBSOLETE')
    parser.add_argument('--senderid_expry', help='OBSOLETE')


def add_external_router_args(parser):
    """Parses out external router arguments"""
    # GCM
    parser.add_argument('--gcm_enabled', help="Enable GCM Bridge",
                        action="store_true", default=False,
                        env_var="GCM_ENABLED")
    label = "GCM Router:"
    parser.add_argument('--gcm_ttl', help="%s Time to Live" % label,
                        type=int, default=60, env_var="GCM_TTL")
    parser.add_argument('--gcm_dryrun',
                        help="%s Dry run (no message sent)" % label,
                        action="store_true", default=False,
                        env_var="GCM_DRYRUN")
    parser.add_argument('--gcm_collapsekey',
                        help="%s string to collapse messages" % label,
                        type=str, default="simplepush",
                        env_var="GCM_COLLAPSEKEY")
    parser.add_argument('--senderid_list', help='SenderIDs to load to S3',
                        type=str, default="{}")
    # FCM
    parser.add_argument('--fcm_enabled', help="Enable FCM Bridge",
                        action="store_true", default=False,
                        env_var="FCM_ENABLED")
    label = "FCM Router:"
    parser.add_argument('--fcm_ttl', help="%s Time to Live" % label,
                        type=int, default=60, env_var="FCM_TTL")
    parser.add_argument('--fcm_dryrun',
                        help="%s Dry run (no message sent)" % label,
                        action="store_true", default=False,
                        env_var="FCM_DRYRUN")
    parser.add_argument('--fcm_collapsekey',
                        help="%s string to collapse messages" % label,
                        type=str, default="simplepush",
                        env_var="FCM_COLLAPSEKEY")
    parser.add_argument('--fcm_auth', help='Auth Key for FCM',
                        type=str, default="")
    parser.add_argument('--fcm_senderid', help='SenderID for FCM',
                        type=str, default="")
    # Apple Push Notification system (APNs) for iOS
    parser.add_argument('--apns_enabled', help="Enable APNS Bridge",
                        action="store_true", default=False,
                        env_var="APNS_ENABLED")
    label = "APNS Router:"
    parser.add_argument('--apns_sandbox', help="%s Use Dev Sandbox" % label,
                        action="store_true", default=False,
                        env_var="APNS_SANDBOX")
    parser.add_argument('--apns_cert_file',
                        help="%s Certificate PEM file" % label,
                        type=str, env_var="APNS_CERT_FILE")
    parser.add_argument('--apns_key_file', help="%s Key PEM file" % label,
                        type=str, env_var="APNS_KEY_FILE")
    # UDP
    parser.add_argument('--wake_timeout',
                        help="UDP: idle timeout before closing socket",
                        type=int, default=0, env_var="WAKE_TIMEOUT")
    parser.add_argument('--wake_pem',
                        help="custom TLS PEM file for remote Wake server",
                        type=str, env_var="WAKE_PEM")
    parser.add_argument('--wake_server',
                        help="remote endpoint for wake-up calls",
                        type=str, default='http://example.com',
                        env_var="WAKE_SERVER")


def _parse_connection(sysargs, use_files=True):
    """Parse out connection node arguments for an autopush node"""
    # For testing, do not use the configuration files since they can
    # produce unexpected results.
    if use_files:  # pragma: nocover
        config_files = shared_config_files + [  # pragma: nocover
            '/etc/autopush_connection.ini',
            'configs/autopush_connection.ini',
            '~/.autopush_connection.ini',
            '.autopush_connection.ini'
        ]
    else:
        config_files = []  # pragma: nocover
    parser = configargparse.ArgumentParser(
        description='Runs a Connection Node.',
        default_config_files=config_files,
        )
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
    parser.add_argument('--auto_ping_interval',
                        help="Interval between Websocket pings", default=0,
                        type=float, env_var="AUTO_PING_INTERVAL")
    parser.add_argument('--auto_ping_timeout',
                        help="Timeout in seconds for Websocket ping replys",
                        default=4, type=float, env_var="AUTO_PING_TIMEOUT")
    parser.add_argument('--max_connections',
                        help="The maximum number of concurrent connections.",
                        default=0, type=int, env_var="MAX_CONNECTIONS")
    parser.add_argument('--close_handshake_timeout',
                        help="The WebSocket closing handshake timeout. Set to "
                        "0 to disable.", default=0, type=int,
                        env_var="CLOSE_HANDSHAKE_TIMEOUT")
    parser.add_argument('--hello_timeout',
                        help="The client handshake timeout. Set to 0 to"
                        "disable.", default=0, type=int,
                        env_var="HELLO_TIMEOUT")

    add_shared_args(parser)
    args = parser.parse_args(sysargs)
    return args, parser


def _parse_endpoint(sysargs, use_files=True):
    """Parses out endpoint arguments for an autoendpoint node"""
    if use_files:  # pragma: nocover
        config_files = shared_config_files + [
            '/etc/autopush_endpoint.ini',
            'configs/autopush_endpoint.ini',
            '~/.autopush_endpoint.ini',
            '.autopush_endpoint.ini'
        ]
    else:
        config_files = []  # pragma: nocover
    parser = configargparse.ArgumentParser(
        description='Runs an Endpoint Node.',
        default_config_files=config_files,
        )
    parser.add_argument('--config-endpoint',
                        help="Endpoint node configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('-p', '--port', help='Public HTTP Endpoint Port',
                        type=int, default=8082, env_var="PORT")
    parser.add_argument('--no_cors', help='Disallow CORS PUTs for update.',
                        action="store_true",
                        default=False, env_var='ALLOW_CORS')
    parser.add_argument('--auth_key', help='Bearer Token source key',
                        type=str, default=[], env_var='AUTH_KEY',
                        action="append")

    add_shared_args(parser)

    args = parser.parse_args(sysargs)
    return args, parser


def make_settings(args, **kwargs):
    """Helper function to make a :class:`AutopushSettings` object"""
    router_conf = {}
    if args.key_hash:
        db.key_hash = args.key_hash
    # Some routers require a websocket to timeout on idle (e.g. UDP)
    if args.wake_pem is not None and args.wake_timeout != 0:
        router_conf["simplepush"] = {"idle": args.wake_timeout,
                                     "server": args.wake_server,
                                     "cert": args.wake_pem}
    if args.apns_enabled:
        # if you have the critical elements for each external router, create it
        if args.apns_cert_file is not None and args.apns_key_file is not None:
            router_conf["apns"] = {"sandbox": args.apns_sandbox,
                                   "cert_file": args.apns_cert_file,
                                   "key_file": args.apns_key_file}
    if args.gcm_enabled:
        # Create a common gcmclient
        try:
            sender_ids = json.loads(args.senderid_list)
        except (ValueError, TypeError):
            log.critical(format="Invalid JSON specified for senderid_list")
            return
        try:
            # This is an init check to verify that things are configured
            # correctly. Otherwise errors may creep in later that go
            # unaccounted.
            sender_ids[sender_ids.keys()[0]]
        except (IndexError, TypeError):
            log.critical(format="No GCM SenderIDs specified or found.")
            return
        router_conf["gcm"] = {"ttl": args.gcm_ttl,
                              "dryrun": args.gcm_dryrun,
                              "max_data": args.max_data,
                              "collapsekey": args.gcm_collapsekey,
                              "senderIDs": sender_ids}
    if args.fcm_enabled:
        # Create a common gcmclient
        if not args.fcm_auth:
            log.critical(format="No Authorization Key found for FCM")
            return
        if not args.fcm_senderid:
            log.critical(format="No SenderID found for FCM")
            return
        router_conf["fcm"] = {"ttl": args.fcm_ttl,
                              "dryrun": args.fcm_dryrun,
                              "max_data": args.max_data,
                              "collapsekey": args.fcm_collapsekey,
                              "auth": args.fcm_auth,
                              "senderid": args.fcm_senderid}

    ami_id = None
    # Not a fan of double negatives, but this makes more understandable args
    if not args.no_aws:
        ami_id = utils.get_amid()

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
        message_tablename=args.message_tablename,
        message_read_throughput=args.message_read_throughput,
        message_write_throughput=args.message_write_throughput,
        router_read_throughput=args.router_read_throughput,
        router_write_throughput=args.router_write_throughput,
        resolve_hostname=args.resolve_hostname,
        wake_timeout=args.wake_timeout,
        ami_id=ami_id,
        **kwargs
    )


def skip_request_logging(handler):
    """Ignores request logging"""
    pass


def mount_health_handlers(site, settings):
    """Create a health check HTTP handler on a cyclone site object"""
    h_kwargs = dict(ap_settings=settings)
    site.add_handlers(".*$", [
        (r"^/status", StatusHandler, h_kwargs),
        (r"^/health", HealthHandler, h_kwargs),
    ])


def connection_main(sysargs=None, use_files=True):
    """Main entry point to setup a connection node, aka the autopush script"""
    args, parser = _parse_connection(sysargs, use_files)
    log_format = "text" if args.human_logs else "json"
    log_level = args.log_level or ("debug" if args.debug else "info")
    sentry_dsn = bool(os.environ.get("SENTRY_DSN"))
    PushLogger.setup_logging(
        "Autopush",
        log_level=log_level,
        log_format=log_format,
        log_output=args.log_output,
        sentry_dsn=sentry_dsn,
        firehose_delivery_stream=args.firehose_stream_name
    )
    # Add some entropy to prevent potential conflicts.
    postfix = os.urandom(4).encode('hex').ljust(8, '0')
    settings = make_settings(
        args,
        port=args.port,
        endpoint_scheme=args.endpoint_scheme,
        endpoint_hostname=args.endpoint_hostname,
        endpoint_port=args.endpoint_port,
        router_scheme="https" if args.router_ssl_key else "http",
        router_hostname=args.router_hostname,
        router_port=args.router_port,
        env=args.env,
        hello_timeout=args.hello_timeout,
        preflight_uaid="deadbeef000000000deadbeef" + postfix,
    )
    if not settings:
        return 1  # pragma: nocover

    # Internal HTTP notification router
    h_kwargs = dict(ap_settings=settings)
    site = cyclone.web.Application([
        (r"/push/([^\/]+)", RouterHandler, h_kwargs),
        (r"/notif/([^\/]+)(/([^\/]+))?", NotificationHandler, h_kwargs),
    ],
        default_host=settings.router_hostname, debug=args.debug,
        log_function=skip_request_logging
    )
    mount_health_handlers(site, settings)

    # Public websocket server
    proto = "wss" if args.ssl_key else "ws"
    factory = WebSocketServerFactory(
        "%s://%s:%s/" % (proto, args.hostname, args.port),
    )
    factory.protocol = PushServerProtocol
    factory.protocol.ap_settings = settings
    factory.setProtocolOptions(
        webStatus=False,
        openHandshakeTimeout=5,
        autoPingInterval=args.auto_ping_interval,
        autoPingTimeout=args.auto_ping_timeout,
        maxConnections=args.max_connections,
        closeHandshakeTimeout=args.close_handshake_timeout,
    )
    settings.factory = factory

    settings.metrics.start()

    # Wrap the WebSocket server in a default resource that exposes the
    # `/status` handler, and delegates to the WebSocket resource for all
    # other requests.
    resource = DefaultResource(WebSocketResource(factory))
    resource.putChild("status", StatusResource())
    site_factory = Site(resource)

    # Start the WebSocket listener.
    if args.ssl_key:
        context_factory = AutopushSSLContextFactory(args.ssl_key,
                                                    args.ssl_cert)
        if args.ssl_dh_param:
            context_factory.getContext().load_tmp_dh(args.ssl_dh_param)

        reactor.listenSSL(args.port, site_factory, context_factory)
    else:
        reactor.listenTCP(args.port, site_factory)

    # Start the internal routing listener.
    if args.router_ssl_key:
        context_factory = AutopushSSLContextFactory(args.router_ssl_key,
                                                    args.router_ssl_cert)
        if args.ssl_dh_param:
            context_factory.getContext().load_tmp_dh(args.ssl_dh_param)
        reactor.listenSSL(args.router_port, site, context_factory)
    else:
        reactor.listenTCP(args.router_port, site)

    reactor.suggestThreadPoolSize(50)

    l = task.LoopingCall(periodic_reporter, settings)
    l.start(1.0)

    # Start the table rotation checker/updater
    l = task.LoopingCall(settings.update_rotating_tables)
    l.start(60)
    reactor.run()


def endpoint_main(sysargs=None, use_files=True):
    """Main entry point to setup an endpoint node, aka the autoendpoint
    script"""
    args, parser = _parse_endpoint(sysargs, use_files)
    log_level = args.log_level or ("debug" if args.debug else "info")
    log_format = "text" if args.human_logs else "json"
    sentry_dsn = bool(os.environ.get("SENTRY_DSN"))
    PushLogger.setup_logging(
        "Autoendpoint",
        log_level=log_level,
        log_format=log_format,
        log_output=args.log_output,
        sentry_dsn=sentry_dsn,
        firehose_delivery_stream=args.firehose_stream_name
    )

    # Add some entropy to prevent potential conflicts.
    postfix = os.urandom(4).encode('hex').ljust(8, '0')
    settings = make_settings(
        args,
        endpoint_scheme=args.endpoint_scheme,
        endpoint_hostname=args.endpoint_hostname or args.hostname,
        endpoint_port=args.endpoint_port,
        enable_cors=not args.no_cors,
        bear_hash_key=args.auth_key,
        preflight_uaid="deadbeef000000000deadbeef" + postfix,
    )
    if not settings:
        return 1

    # Endpoint HTTP router
    h_kwargs = dict(ap_settings=settings)
    site = cyclone.web.Application([
        (r"/push/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
         EndpointHandler, h_kwargs),
        (r"/spush/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
         SimplePushHandler, h_kwargs),
        (r"/wpush/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
         WebPushHandler, h_kwargs),
        (r"/m/([^\/]+)", MessageHandler, h_kwargs),
        (r"/v1/([^\/]+)/([^\/]+)/registration(?:/([^\/]+))"
            "?(?:/subscription)?(?:/([^\/]+))?",
         RegistrationHandler, h_kwargs),
        (r"/v1/err(?:/([^\/]+))?", LogCheckHandler, h_kwargs),
    ],
        default_host=settings.hostname, debug=args.debug,
        log_function=skip_request_logging
    )
    site.protocol = LimitedHTTPConnection
    site.protocol.maxData = settings.max_data
    mount_health_handlers(site, settings)

    settings.metrics.start()

    # start the senderIDs refresh timer
    if args.ssl_key:
        context_factory = AutopushSSLContextFactory(args.ssl_key,
                                                    args.ssl_cert)
        if args.ssl_dh_param:
            context_factory.getContext().load_tmp_dh(args.ssl_dh_param)
        reactor.listenSSL(args.port, site, context_factory)
    else:
        reactor.listenTCP(args.port, site)

    # Start the table rotation checker/updater
    l = task.LoopingCall(settings.update_rotating_tables)
    l.start(60)

    reactor.suggestThreadPoolSize(50)
    reactor.run()
