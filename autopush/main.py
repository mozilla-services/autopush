"""autopush/autoendpoint daemon scripts"""
import json
import os
from argparse import Namespace  # noqa

from twisted.application.internet import (
    TCPServer,
    TimerService,
    SSLServer,
    StreamServerEndpointService,
)
from twisted.application.service import MultiService
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory  # noqa
from twisted.logger import Logger
from typing import (  # noqa
    Any,
    Optional,
    Sequence,
    Union
)

import autopush.db as db
from autopush.http import (
    InternalRouterHTTPFactory,
    EndpointHTTPFactory,
    MemUsageHTTPFactory
)
import autopush.utils as utils
from autopush.exceptions import InvalidSettings
from autopush.haproxy import HAProxyServerEndpoint
from autopush.logging import PushLogger
from autopush.main_argparse import parse_connection, parse_endpoint
from autopush.settings import AutopushSettings
from autopush.websocket import (
    ConnectionWSSite,
    PushServerFactory,
    periodic_reporter,
)

log = Logger()


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
            raise InvalidSettings(
                "Invalid JSON specified for APNS config options")
    if args.gcm_enabled:
        # Create a common gcmclient
        try:
            sender_ids = json.loads(args.senderid_list)
        except (ValueError, TypeError):
            raise InvalidSettings("Invalid JSON specified for senderid_list")
        try:
            # This is an init check to verify that things are configured
            # correctly. Otherwise errors may creep in later that go
            # unaccounted.
            sender_ids[sender_ids.keys()[0]]
        except (IndexError, TypeError):
            raise InvalidSettings("No GCM SenderIDs specified or found.")
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
            raise InvalidSettings("Invalid JSON specified for client_certs")
        if client_certs_arg:
            if not args.ssl_key:
                raise InvalidSettings("client_certs specified without SSL "
                                      "enabled (no ssl_key specified)")
            client_certs = {}
            for name, sigs in client_certs_arg.iteritems():
                if not isinstance(sigs, list):
                    raise InvalidSettings(
                        "Invalid JSON specified for client_certs")
                for sig in sigs:
                    sig = sig.upper()
                    if (not name or not utils.CLIENT_SHA256_RE.match(sig) or
                            sig in client_certs):
                        raise InvalidSettings("Invalid client_certs argument")
                    client_certs[sig] = name

    if args.fcm_enabled:
        # Create a common gcmclient
        if not args.fcm_auth:
            raise InvalidSettings("No Authorization Key found for FCM")
        if not args.fcm_senderid:
            raise InvalidSettings("No SenderID found for FCM")
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
        memusage_port=args.memusage_port,
        ssl_key=args.ssl_key,
        ssl_cert=args.ssl_cert,
        ssl_dh_param=args.ssl_dh_param,
        **kwargs
    )


class AutopushMultiService(MultiService):

    shared_config_files = (
        '/etc/autopush_shared.ini',
        'configs/autopush_shared.ini',
        '~/.autopush_shared.ini',
        '.autopush_shared.ini',
    )

    config_files = None  # type: Sequence[str]
    logger_name = None   # type: str

    THREAD_POOL_SIZE = 50

    def __init__(self, settings):
        # type: (AutopushSettings) -> None
        super(AutopushMultiService, self).__init__()
        self.settings = settings

    @staticmethod
    def parse_args(config_files, args):
        # type: (Sequence[str], Sequence[str]) -> Namespace
        """Parse command line args via argparse"""
        raise NotImplementedError  # pragma: nocover

    def setup(self, rotate_tables=True):
        # type: (bool) -> None
        """Initialize the services"""
        raise NotImplementedError  # pragma: nocover

    def add_maybe_ssl(self, port, factory, ssl_cf):
        # type: (int, ServerFactory, Optional[Any]) -> None
        """Add a Service from factory, optionally behind TLS"""
        self.addService(
            SSLServer(port, factory, contextFactory=ssl_cf, reactor=reactor)
            if ssl_cf else
            TCPServer(port, factory, reactor=reactor)
        )

    def add_timer(self, *args, **kwargs):
        """Add a TimerService"""
        self.addService(TimerService(*args, **kwargs))

    def add_memusage(self):
        """Add the memusage Service"""
        factory = MemUsageHTTPFactory(self.settings)
        self.addService(
            TCPServer(self.settings.memusage_port, factory, reactor=reactor))

    def run(self):
        """Start the services and run the reactor"""
        reactor.suggestThreadPoolSize(self.THREAD_POOL_SIZE)
        self.startService()
        reactor.run()

    @classmethod
    def _from_argparse(cls, ns, **kwargs):
        # type: (Namespace, **Any) -> AutopushMultiService
        """Create an instance from argparse/additional kwargs"""
        # Add some entropy to prevent potential conflicts.
        postfix = os.urandom(4).encode('hex').ljust(8, '0')
        settings = make_settings(
            ns,
            debug=ns.debug,
            preflight_uaid="deadbeef000000000deadbeef" + postfix,
            **kwargs
        )
        return cls(settings)

    @classmethod
    def main(cls, args=None, use_files=True):
        # type: (Sequence[str], bool) -> Any
        """Entry point to autopush's main command line scripts.

        aka autopush/autoendpoint.

        """
        ns = cls.parse_args(cls.config_files if use_files else [], args)
        PushLogger.setup_logging(
            cls.logger_name,
            log_level=ns.log_level or ("debug" if ns.debug else "info"),
            log_format="text" if ns.human_logs else "json",
            log_output=ns.log_output,
            sentry_dsn=bool(os.environ.get("SENTRY_DSN")),
            firehose_delivery_stream=ns.firehose_stream_name
        )
        try:
            app = cls.from_argparse(ns)
        except InvalidSettings as e:
            log.critical(str(e))
            return 1

        app.setup()
        app.run()


class EndpointApplication(AutopushMultiService):
    """The autoendpoint application"""

    config_files = AutopushMultiService.shared_config_files + (
        '/etc/autopush_endpoint.ini',
        'configs/autopush_endpoint.ini',
        '~/.autopush_endpoint.ini',
        '.autopush_endpoint.ini'
    )

    parse_args = staticmethod(parse_endpoint)  # type: ignore
    logger_name = "Autoendpoint"

    endpoint_factory = EndpointHTTPFactory

    def setup(self, rotate_tables=True):
        self.settings.metrics.start()

        self.add_endpoint()
        if self.settings.memusage_port:
            self.add_memusage()

        # Start the table rotation checker/updater
        if rotate_tables:
            self.add_timer(60, self.settings.update_rotating_tables)

    def add_endpoint(self):
        """Start the Endpoint HTTP router"""
        settings = self.settings

        factory = self.endpoint_factory(settings)
        factory.protocol.maxData = settings.max_data
        factory.add_health_handlers()
        ssl_cf = factory.ssl_cf()
        self.add_maybe_ssl(settings.port, factory, ssl_cf)

        if settings.proxy_protocol_port:
            ep = HAProxyServerEndpoint(
                reactor,
                settings.proxy_protocol_port,
                ssl_cf
            )
            self.addService(StreamServerEndpointService(ep, factory))

    @classmethod
    def from_argparse(cls, ns):
        # type: (Namespace) -> AutopushMultiService
        return super(EndpointApplication, cls)._from_argparse(
            ns,
            port=ns.port,
            endpoint_scheme=ns.endpoint_scheme,
            endpoint_hostname=ns.endpoint_hostname or ns.hostname,
            endpoint_port=ns.endpoint_port,
            enable_cors=not ns.no_cors,
            bear_hash_key=ns.auth_key,
            proxy_protocol_port=ns.proxy_protocol_port,
        )


class ConnectionApplication(AutopushMultiService):
    """The autopush application"""

    config_files = AutopushMultiService.shared_config_files + (
        '/etc/autopush_connection.ini',
        'configs/autopush_connection.ini',
        '~/.autopush_connection.ini',
        '.autopush_connection.ini'
    )

    parse_args = staticmethod(parse_connection)  # type: ignore
    logger_name = "Autopush"

    internal_router_factory = InternalRouterHTTPFactory
    websocket_factory = PushServerFactory
    websocket_site_factory = ConnectionWSSite

    def setup(self, rotate_tables=True):
        self.settings.metrics.start()

        self.add_internal_router()
        if self.settings.memusage_port:
            self.add_memusage()

        self.add_websocket()

        # Start the table rotation checker/updater
        if rotate_tables:
            self.add_timer(60, self.settings.update_rotating_tables)

    def add_internal_router(self):
        """Start the internal HTTP notification router"""
        factory = self.internal_router_factory(self.settings)
        factory.add_health_handlers()
        self.add_maybe_ssl(self.settings.router_port, factory,
                           factory.ssl_cf())

    def add_websocket(self):
        """Start the public WebSocket server"""
        settings = self.settings
        ws_factory = self.websocket_factory(settings)
        site_factory = self.websocket_site_factory(settings, ws_factory)
        self.add_maybe_ssl(settings.port, site_factory, site_factory.ssl_cf())
        self.add_timer(1.0, periodic_reporter, settings, ws_factory)

    @classmethod
    def from_argparse(cls, ns):
        # type: (Namespace) -> AutopushMultiService
        return super(ConnectionApplication, cls)._from_argparse(
            ns,
            port=ns.port,
            endpoint_scheme=ns.endpoint_scheme,
            endpoint_hostname=ns.endpoint_hostname,
            endpoint_port=ns.endpoint_port,
            router_scheme="https" if ns.router_ssl_key else "http",
            router_hostname=ns.router_hostname,
            router_port=ns.router_port,
            env=ns.env,
            hello_timeout=ns.hello_timeout,
            router_ssl_key=ns.router_ssl_key,
            router_ssl_cert=ns.router_ssl_cert,
            auto_ping_interval=ns.auto_ping_interval,
            auto_ping_timeout=ns.auto_ping_timeout,
            max_connections=ns.max_connections,
            close_handshake_timeout=ns.close_handshake_timeout,
        )
