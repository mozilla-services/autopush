"""autopush/autoendpoint daemon scripts"""
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
from twisted.internet.defer import inlineCallbacks
from twisted.internet.protocol import ServerFactory  # noqa
from twisted.logger import Logger
from typing import (  # noqa
    Any,
    Optional,
    Sequence,
)

from autopush.http import (
    InternalRouterHTTPFactory,
    EndpointHTTPFactory,
    MemUsageHTTPFactory,
    agent_from_settings
)
import autopush.utils as utils
import autopush.logging as logging
from autopush.exceptions import InvalidSettings
from autopush.db import DatabaseManager
from autopush.haproxy import HAProxyServerEndpoint
from autopush.logging import PushLogger
from autopush.main_argparse import parse_connection, parse_endpoint
from autopush.router import routers_from_settings
from autopush.settings import AutopushSettings
from autopush.websocket import (
    ConnectionWSSite,
    PushServerFactory,
)

log = Logger()


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
        self.db = DatabaseManager.from_settings(settings)
        self.agent = agent_from_settings(settings)

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
        factory = MemUsageHTTPFactory(self.settings, None)
        self.addService(
            TCPServer(self.settings.memusage_port, factory, reactor=reactor))

    def run(self):
        """Start the services and run the reactor"""
        reactor.suggestThreadPoolSize(self.THREAD_POOL_SIZE)
        self.startService()
        reactor.run()

    @inlineCallbacks
    def stopService(self):
        yield self.agent._pool.closeCachedConnections()
        yield super(AutopushMultiService, self).stopService()

    @classmethod
    def _from_argparse(cls, ns, **kwargs):
        # type: (Namespace, **Any) -> AutopushMultiService
        """Create an instance from argparse/additional kwargs"""
        # Add some entropy to prevent potential conflicts.
        postfix = os.urandom(4).encode('hex').ljust(8, '0')
        settings = AutopushSettings.from_argparse(
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
        if not ns.no_aws:
            logging.HOSTNAME = utils.get_ec2_instance_id()
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

    def __init__(self, *args, **kwargs):
        super(EndpointApplication, self).__init__(*args, **kwargs)
        self.routers = routers_from_settings(self.settings, self.db,
                                             self.agent)

    def setup(self, rotate_tables=True):
        self.db.setup(self.settings.preflight_uaid)

        self.add_endpoint()
        if self.settings.memusage_port:
            self.add_memusage()

        # Start the table rotation checker/updater
        if rotate_tables:
            self.add_timer(60, self.db.update_rotating_tables)

    def add_endpoint(self):
        """Start the Endpoint HTTP router"""
        settings = self.settings

        factory = self.endpoint_factory(settings, self.db, self.routers)
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
            cors=not ns.no_cors,
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

    def __init__(self, *args, **kwargs):
        super(ConnectionApplication, self).__init__(*args, **kwargs)
        self.clients = {}

    def setup(self, rotate_tables=True):
        self.db.setup(self.settings.preflight_uaid)

        self.add_internal_router()
        if self.settings.memusage_port:
            self.add_memusage()

        self.add_websocket()

        # Start the table rotation checker/updater
        if rotate_tables:
            self.add_timer(60, self.db.update_rotating_tables)

    def add_internal_router(self):
        """Start the internal HTTP notification router"""
        factory = self.internal_router_factory(
            self.settings, self.db, self.clients)
        factory.add_health_handlers()
        self.add_maybe_ssl(self.settings.router_port, factory,
                           factory.ssl_cf())

    def add_websocket(self):
        """Start the public WebSocket server"""
        settings = self.settings
        ws_factory = self.websocket_factory(settings, self.db, self.agent,
                                            self.clients)
        site_factory = self.websocket_site_factory(settings, ws_factory)
        self.add_maybe_ssl(settings.port, site_factory, site_factory.ssl_cf())

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
