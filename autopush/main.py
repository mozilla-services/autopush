"""autopush/autoendpoint daemon scripts"""
import json
import os

import configargparse
import cyclone.web
from autobahn.twisted.resource import WebSocketResource
from twisted.internet import reactor, task
from twisted.internet.endpoints import SSL4ServerEndpoint, TCP4ServerEndpoint
from twisted.internet.tcp import Port  # noqa
from twisted.logger import Logger
from twisted.web.server import Site
from typing import Any, Callable  # noqa

import autopush.db as db
import autopush.utils as utils
from autopush.logging import PushLogger
from autopush.settings import AutopushSettings
from autopush.ssl import AutopushSSLContextFactory
from autopush.web.health import (
    HealthHandler,
    MemUsageHandler,
    StatusHandler
)
from autopush.web.limitedhttpconnection import LimitedHTTPConnection
from autopush.web.log_check import LogCheckHandler
from autopush.web.message import MessageHandler
from autopush.web.simplepush import SimplePushHandler
from autopush.web.registration import RegistrationHandler
from autopush.web.webpush import WebPushHandler
from autopush.websocket import (
    DefaultResource,
    NotificationHandler,
    PushServerFactory,
    RouterHandler,
    StatusResource,
    periodic_reporter,
)

shared_config_files = [
    '/etc/autopush_shared.ini',
    'configs/autopush_shared.ini',
    '~/.autopush_shared.ini',
    '.autopush_shared.ini',
]
log = Logger()

# These are the known entry points for autopush. These are used here and in
# testing for consistency.
endpoint_paths = {
    'route': r"/push/([^\/]+)",
    'notification': r"/notif/([^\/]+)(/([^\/]+))?",
    'simple': r"/spush/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
    'webpush': r"/wpush/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
    'message': r"/m/(?P<message_id>[^\/]+)",
    'registration': r"/v1/(?P<router_type>[^\/]+)/(?P<router_token>[^\/]+)/"
                    r"registration(?:/(?P<uaid>[^\/]+))?(?:/subscription)?"
                    r"(?:/(?P<chid>[^\/]+))?",
    'logcheck': r"/v1/err(?:/(?P<err_type>[^\/]+))?",
    'status': r"^/status",
    'health': r"^/health",
    'memusage': r"^/_memusage",
}


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
                        type=str, default=None, env_var="SSL_DH_PARAM")
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
    parser.add_argument('--connection_timeout',
                        help="Seconds to wait for connection timeout",
                        type=int, default=1, env_var="CONNECTION_TIMEOUT")
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
    parser.add_argument('--msg_limit', help="Max limit for messages per uaid "
                        "before reset", type=int, default="100",
                        env_var="MSG_LIMIT")
    parser.add_argument('--memusage_port',
                        help="Enable the debug _memusage API on Port",
                        type=int, default=None,
                        env_var='MEMUSAGE_PORT')
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
    parser.add_argument('--proxy_protocol', help="OBSOLETE")
    # old APNs args
    parser.add_argument('--apns_enabled', help="OBSOLETE")
    parser.add_argument('--apns_sandbox', help="OBSOLETE")
    parser.add_argument('--apns_cert_file', help="OBSOLETE")
    parser.add_argument('--apns_key_file', help="OBSOLETE")


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
    parser.add_argument('--senderid_list', help='GCM SenderIDs/auth keys',
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
    # credentials consist of JSON struct containing a channel type
    # followed by the settings,
    # e.g. {'firefox':{'cert': 'path.cert', 'key': 'path.key',
    #                  'sandbox': false}, ... }
    parser.add_argument('--apns_creds', help="JSON dictionary of "
                                             "APNS settings",
                        type=str, default="",
                        env_var="APNS_CREDS")
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
    parser.add_argument('--client_certs',
                        help="Allowed TLS client certificates",
                        type=str, env_var='CLIENT_CERTS', default="{}")
    parser.add_argument('--proxy_protocol_port',
                        help="Enable a secondary Endpoint Port with HAProxy "
                        "Proxy Protocol handling",
                        type=int, default=None,
                        env_var='PROXY_PROTOCOL_PORT')

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
    if args.apns_creds:
        # if you have the critical elements for each external router, create it
        try:
            router_conf["apns"] = json.loads(args.apns_creds)
        except (ValueError, TypeError):
            log.critical(format="Invalid JSON specified for APNS config "
                                "options")
            return
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

    client_certs = None
    # endpoint only
    if getattr(args, 'client_certs', None):
        try:
            client_certs_arg = json.loads(args.client_certs)
        except (ValueError, TypeError):
            log.critical(format="Invalid JSON specified for client_certs")
            return
        if client_certs_arg:
            if not args.ssl_key:
                log.critical(format="client_certs specified without SSL "
                                    "enabled (no ssl_key specified)")
                return
            client_certs = {}
            for name, sigs in client_certs_arg.iteritems():
                if not isinstance(sigs, list):
                    log.critical(
                        format="Invalid JSON specified for client_certs")
                    return
                for sig in sigs:
                    sig = sig.upper()
                    if (not name or not utils.CLIENT_SHA256_RE.match(sig) or
                            sig in client_certs):
                        log.critical(format="Invalid client_certs argument")
                        return
                    client_certs[sig] = name

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
        client_certs=client_certs,
        msg_limit=args.msg_limit,
        connect_timeout=args.connection_timeout,
        **kwargs
    )


def skip_request_logging(handler):
    """Ignores request logging"""
    pass


def mount_health_handlers(site, settings):
    """Create a health check HTTP handler on a cyclone site object"""
    h_kwargs = dict(ap_settings=settings)
    site.add_handlers(".*$", [
        (endpoint_paths['status'], StatusHandler, h_kwargs),
        (endpoint_paths['health'], HealthHandler, h_kwargs),
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
        debug=args.debug,
    )
    if not settings:
        return 1  # pragma: nocover

    # Internal HTTP notification router
    h_kwargs = dict(ap_settings=settings)
    site = cyclone.web.Application([
        (endpoint_paths['route'], RouterHandler, h_kwargs),
        (endpoint_paths['notification'], NotificationHandler, h_kwargs),
    ],
        default_host=settings.router_hostname, debug=args.debug,
        log_function=skip_request_logging
    )
    site.noisy = args.debug
    mount_health_handlers(site, settings)

    # Public websocket server
    proto = "wss" if args.ssl_key else "ws"
    factory = PushServerFactory(
        settings,
        "%s://%s:%s/" % (proto, args.hostname, args.port),
    )
    factory.setProtocolOptions(
        webStatus=False,
        openHandshakeTimeout=5,
        autoPingInterval=args.auto_ping_interval,
        autoPingTimeout=args.auto_ping_timeout,
        maxConnections=args.max_connections,
        closeHandshakeTimeout=args.close_handshake_timeout,
    )

    settings.metrics.start()

    # Wrap the WebSocket server in a default resource that exposes the
    # `/status` handler, and delegates to the WebSocket resource for all
    # other requests.
    resource = DefaultResource(WebSocketResource(factory))
    resource.putChild("status", StatusResource())
    site_factory = Site(resource)
    # Silence starting/stopping messages
    site_factory.noisy = args.debug
    site.noisy = args.debug

    # Start the WebSocket listener.
    if args.ssl_key:
        context_factory = AutopushSSLContextFactory(
            args.ssl_key,
            args.ssl_cert,
            dh_file=args.ssl_dh_param)
        reactor.listenSSL(args.port, site_factory, context_factory)
    else:
        reactor.listenTCP(args.port, site_factory)

    # Start the internal routing listener.
    if args.router_ssl_key:
        context_factory = AutopushSSLContextFactory(
            args.router_ssl_key,
            args.router_ssl_cert,
            dh_file=args.ssl_dh_param)
        reactor.listenSSL(args.router_port, site, context_factory)
    else:
        reactor.listenTCP(args.router_port, site)

    reactor.suggestThreadPoolSize(50)
    start_looping_call(1.0, periodic_reporter, settings, factory)
    # Start the table rotation checker/updater
    start_looping_call(60, settings.update_rotating_tables)
    if args.memusage_port:
        create_memusage_site(settings, args.memusage_port, args.debug)
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
        debug=args.debug
    )
    if not settings:
        return 1

    # Endpoint HTTP router
    h_kwargs = dict(ap_settings=settings)
    site = cyclone.web.Application([
        (endpoint_paths['simple'], SimplePushHandler, h_kwargs),
        (endpoint_paths['webpush'], WebPushHandler, h_kwargs),
        (endpoint_paths['message'], MessageHandler, h_kwargs),
        (endpoint_paths['registration'], RegistrationHandler, h_kwargs),
        (endpoint_paths['logcheck'], LogCheckHandler, h_kwargs),
    ],
        default_host=settings.hostname, debug=args.debug,
        log_function=skip_request_logging
    )
    site.protocol = LimitedHTTPConnection
    site.protocol.maxData = settings.max_data
    mount_health_handlers(site, settings)
    site.noisy = args.debug

    settings.metrics.start()

    if args.ssl_key:
        ssl_cf = AutopushSSLContextFactory(
            args.ssl_key,
            args.ssl_cert,
            dh_file=args.ssl_dh_param,
            require_peer_certs=settings.enable_tls_auth)
        endpoint = SSL4ServerEndpoint(reactor, args.port, ssl_cf)
    else:
        ssl_cf = None
        endpoint = TCP4ServerEndpoint(reactor, args.port)
    endpoint.listen(site)

    if args.proxy_protocol_port:
        from autopush.haproxy import HAProxyServerEndpoint
        pendpoint = HAProxyServerEndpoint(
            reactor,
            args.proxy_protocol_port,
            ssl_cf)
        pendpoint.listen(site)

    reactor.suggestThreadPoolSize(50)
    # Start the table rotation checker/updater
    start_looping_call(60, settings.update_rotating_tables)
    if args.memusage_port:
        create_memusage_site(settings, args.memusage_port, args.debug)
    reactor.run()


def start_looping_call(interval, func, *args, **kwargs):
    # type: (int, Callable[..., Any], *Any, **Any) -> None
    """Fire off a LoopingCall of interval, logging errors."""
    lc = task.LoopingCall(func, *args, **kwargs)
    lc.start(interval).addErrback(
        lambda failure: log.failure(
            "Error in LoopingCall {name}", name=func.__name__, failure=failure)
    )


def create_memusage_site(settings, port, debug):
    # type: (AutopushSettings, int, bool) -> Port
    """Setup MemUsageHandler on a specific port"""
    h_kwargs = dict(ap_settings=settings)
    site = cyclone.web.Application(
        [(endpoint_paths['memusage'], MemUsageHandler, h_kwargs)],
        default_host=settings.hostname,
        debug=debug,
        log_function=skip_request_logging
    )
    site.noisy = debug
    return reactor.listenTCP(port, site)
