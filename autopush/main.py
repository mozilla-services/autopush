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
    Dict,
    Optional,
    Sequence,
)

from autopush import constants
from autopush.http import (
    InternalRouterHTTPFactory,
    EndpointHTTPFactory,
    MemUsageHTTPFactory,
    agent_from_config
)
import autopush.utils as utils
import autopush.logging as logging
from autopush.config import AutopushConfig
from autopush.db import DatabaseManager, DynamoDBResource  # noqa
from autopush.exceptions import InvalidConfig
from autopush.haproxy import HAProxyServerEndpoint
from autopush.logging import PushLogger
from autopush.main_argparse import parse_connection, parse_endpoint
from autopush.metrics import periodic_reporter
from autopush.router import routers_from_config
from autopush.ssl import (
    monkey_patch_ssl_wrap_socket,
    undo_monkey_patch_ssl_wrap_socket,
)
from autopush.webpush_server import WebPushServer
from autopush.websocket import (
    ConnectionWSSite,
    PushServerFactory,
)
from autopush.websocket import PushServerProtocol  # noqa

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

    def __init__(self, conf, resource=None):
        # type: (AutopushConfig, DynamoDBResource) -> None
        super(AutopushMultiService, self).__init__()
        self.conf = conf
        self.db = DatabaseManager.from_config(conf, resource=resource)
        self.agent = agent_from_config(conf)

    @staticmethod
    def parse_args(config_files, args):
        # type: (Sequence[str], Sequence[str]) -> Namespace
        """Parse command line args via argparse"""
        raise NotImplementedError  # pragma: nocover

    def setup(self, rotate_tables=True):
        # type: (bool) -> None
        """Initialize the services"""
        if not self.conf.no_sslcontext_cache:
            monkey_patch_ssl_wrap_socket()

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
        factory = MemUsageHTTPFactory(self.conf, None)
        self.addService(
            TCPServer(self.conf.memusage_port, factory, reactor=reactor))

    def run(self):
        """Start the services and run the reactor"""
        reactor.suggestThreadPoolSize(constants.THREAD_POOL_SIZE)
        self.startService()
        reactor.run()

    @inlineCallbacks
    def stopService(self):
        yield self.agent._pool.closeCachedConnections()
        yield super(AutopushMultiService, self).stopService()
        if not self.conf.no_sslcontext_cache:
            undo_monkey_patch_ssl_wrap_socket()

    @classmethod
    def _from_argparse(cls, ns, resource=None, **kwargs):
        # type: (Namespace, DynamoDBResource, **Any) -> AutopushMultiService
        """Create an instance from argparse/additional kwargs"""
        # Add some entropy to prevent potential conflicts.
        postfix = os.urandom(4).encode('hex').ljust(8, '0')
        conf = AutopushConfig.from_argparse(
            ns,
            debug=ns.debug,
            preflight_uaid="deadbeef00000000deadbeef" + postfix,
            **kwargs
        )
        return cls(conf, resource=resource)

    @classmethod
    def main(cls, args=None, use_files=True, resource=None):
        # type: (Sequence[str], bool, DynamoDBResource) -> Any
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
            cls.argparse = cls.from_argparse(ns, resource=resource)
            app = cls.argparse
        except InvalidConfig as e:
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

    def __init__(self, conf, resource=None):
        # type: (AutopushConfig, DynamoDBResource) -> None
        super(EndpointApplication, self).__init__(conf, resource=resource)
        self.routers = routers_from_config(conf, self.db, self.agent)

    def setup(self, rotate_tables=True):
        super(EndpointApplication, self).setup(rotate_tables)

        self.db.setup(self.conf.preflight_uaid)

        self.add_endpoint()
        if self.conf.memusage_port:
            self.add_memusage()

        # Start the table rotation checker/updater
        if rotate_tables:
            self.add_timer(60, self.db.update_rotating_tables)
        self.add_timer(15, periodic_reporter, self.db.metrics,
                       prefix='autoendpoint')

    def add_endpoint(self):
        """Start the Endpoint HTTP router"""
        conf = self.conf

        factory = self.endpoint_factory(conf, self.db, self.routers)
        factory.protocol.maxData = conf.max_data
        factory.add_health_handlers()
        ssl_cf = factory.ssl_cf()
        self.add_maybe_ssl(conf.port, factory, ssl_cf)

        if conf.proxy_protocol_port:
            ep = HAProxyServerEndpoint(
                reactor,
                conf.proxy_protocol_port,
                ssl_cf
            )
            self.addService(StreamServerEndpointService(ep, factory))

    @classmethod
    def from_argparse(cls, ns, resource=None):
        # type: (Namespace, DynamoDBResource) -> AutopushMultiService
        return super(EndpointApplication, cls)._from_argparse(
            ns,
            port=ns.port,
            endpoint_scheme=ns.endpoint_scheme,
            endpoint_hostname=ns.endpoint_hostname or ns.hostname,
            endpoint_port=ns.endpoint_port,
            cors=not ns.no_cors,
            bear_hash_key=ns.auth_key,
            proxy_protocol_port=ns.proxy_protocol_port,
            aws_ddb_endpoint=ns.aws_ddb_endpoint,
            resource=resource
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

    def __init__(self, conf, resource=None):
        # type: (AutopushConfig, DynamoDBResource) -> None
        super(ConnectionApplication, self).__init__(
            conf,
            resource=resource
        )
        self.clients = {}  # type: Dict[str, PushServerProtocol]

    def setup(self, rotate_tables=True):
        super(ConnectionApplication, self).setup(rotate_tables)

        self.db.setup(self.conf.preflight_uaid)

        self.add_internal_router()
        if self.conf.memusage_port:
            self.add_memusage()

        self.add_websocket()

        # Start the table rotation checker/updater
        if rotate_tables:
            self.add_timer(60, self.db.update_rotating_tables)
        self.add_timer(15, periodic_reporter, self.db.metrics)

    def add_internal_router(self):
        """Start the internal HTTP notification router"""
        factory = self.internal_router_factory(
            self.conf, self.db, self.clients)
        factory.add_health_handlers()
        self.add_maybe_ssl(self.conf.router_port, factory, factory.ssl_cf())

    def add_websocket(self):
        """Start the public WebSocket server"""
        conf = self.conf
        ws_factory = self.websocket_factory(conf, self.db, self.agent,
                                            self.clients)
        site_factory = self.websocket_site_factory(conf, ws_factory)
        self.add_maybe_ssl(conf.port, site_factory, site_factory.ssl_cf())

    @classmethod
    def from_argparse(cls, ns, resource=None):
        # type: (Namespace, DynamoDBResource) -> AutopushMultiService
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
            router_ssl=dict(
                key=ns.router_ssl_key,
                cert=ns.router_ssl_cert,
                dh_param=ns.ssl_dh_param
            ),
            auto_ping_interval=ns.auto_ping_interval,
            auto_ping_timeout=ns.auto_ping_timeout,
            max_connections=ns.max_connections,
            close_handshake_timeout=ns.close_handshake_timeout,
            aws_ddb_endpoint=ns.aws_ddb_endpoint,
            resource=resource
        )


class RustConnectionApplication(AutopushMultiService):
    """The autopush application"""

    config_files = AutopushMultiService.shared_config_files + (
        '/etc/autopush_connection.ini',
        'configs/autopush_connection.ini',
        '~/.autopush_connection.ini',
        '.autopush_connection.ini'
    )

    parse_args = staticmethod(parse_connection)  # type: ignore
    logger_name = "AutopushRust"
    push_server = None

    def __init__(self, conf):
        # type: (AutopushConfig) -> None
        super(RustConnectionApplication, self).__init__(conf)

    def setup(self, rotate_tables=True):
        super(RustConnectionApplication, self).setup(rotate_tables)

        self.db.setup(self.conf.preflight_uaid)

        if self.conf.memusage_port:
            self.add_memusage()

        self.push_server = WebPushServer(self.conf, self.db, num_threads=10)

    def run(self):
        try:
            self.push_server.run()
        finally:
            self.stopService()

    @inlineCallbacks
    def stopService(self):
        yield super(RustConnectionApplication, self).stopService()

    @classmethod
    def from_argparse(cls, ns, resource=None):
        # type: (Namespace, DynamoDBResource) -> AutopushMultiService
        return super(RustConnectionApplication, cls)._from_argparse(
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
            router_ssl=dict(
                key=ns.router_ssl_key,
                cert=ns.router_ssl_cert,
                dh_param=ns.ssl_dh_param
            ),
            # XXX: default is for autopush_rs
            auto_ping_interval=ns.auto_ping_interval or 300,
            auto_ping_timeout=ns.auto_ping_timeout,
            max_connections=ns.max_connections,
            close_handshake_timeout=ns.close_handshake_timeout,
            aws_ddb_endpoint=ns.aws_ddb_endpoint,
            resource=resource
        )

    @classmethod
    def main(cls, args=None, use_files=True, resource=None):
        # type: (Sequence[str], bool, DynamoDBResource) -> Any
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
            app = cls.from_argparse(ns, resource=resource)
        except InvalidConfig as e:
            log.critical(str(e))
            return 1

        app.setup()
        app.run()
