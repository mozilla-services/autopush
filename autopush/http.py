"""HTTP Server Protocol Factories on top of cyclone"""
from typing import (  # noqa
    Any,
    Callable,
    Dict,
    Optional,
    Sequence,
    Tuple,
    Type
)

import cyclone.web
from twisted.internet import reactor
from twisted.web.client import (
    _HTTP11ClientFactory,
    Agent,
    HTTPConnectionPool,
)

from autopush.base import BaseHandler
from autopush.config import AutopushConfig  # noqa
from autopush.db import DatabaseManager
from autopush.router import routers_from_config
from autopush.router.interface import IRouter  # noqa
from autopush.ssl import AutopushSSLContextFactory  # noqa
from autopush.web.health import (
    HealthHandler,
    MemUsageHandler,
    StatusHandler
)
from autopush.web.base import NotFoundHandler
from autopush.web.limitedhttpconnection import LimitedHTTPConnection
from autopush.web.log_check import LogCheckHandler
from autopush.web.message import MessageHandler
from autopush.web.registration import (
    ChannelRegistrationHandler,
    NewRegistrationHandler,
    SubRegistrationHandler,
    UaidRegistrationHandler,
)
from autopush.web.webpush import WebPushHandler
from autopush.websocket import (
    NotificationHandler,
    RouterHandler,
)
from autopush.websocket import PushServerProtocol  # noqa
from autopush.web.dockerflow import VersionHandler, LBHeartbeatHandler

APHandlers = Sequence[Tuple[str, Type[BaseHandler]]]
CycloneLogger = Callable[[BaseHandler], None]


def skip_request_logging(handler):
    # type: (cyclone.web.RequestHandler) -> None
    """Skip cyclone's request logging"""


class BaseHTTPFactory(cyclone.web.Application):

    ap_handlers = None  # type: APHandlers

    health_ap_handlers = (
        (r"^/status", StatusHandler),
        (r"^/health", HealthHandler),
        # DockerFlow checks
        (r"^/__version__", VersionHandler),
        (r"^/__heartbeat__", StatusHandler),
        (r"^/__lbheartbeat__", LBHeartbeatHandler),
    )

    def __init__(self,
                 conf,           # type: AutopushConfig
                 db,             # type: DatabaseManager
                 handlers=None,  # type: APHandlers
                 log_function=skip_request_logging,  # type: CycloneLogger
                 **kwargs):
        # type: (...) -> None
        self.conf = conf
        self.db = db
        self.noisy = conf.debug

        cyclone.web.Application.__init__(
            self,
            handlers=self.ap_handlers if handlers is None else handlers,
            default_host=self._hostname,
            debug=conf.debug,
            log_function=log_function,
            **kwargs
        )

    def add_health_handlers(self):
        """Add the health check HTTP handlers"""
        self.add_handlers(".*$", self.health_ap_handlers)

    @property
    def _hostname(self):
        return self.conf.hostname

    @classmethod
    def for_handler(cls,
                    handler_cls,    # Type[BaseHTTPFactory]
                    conf,           # type: AutopushConfig
                    db=None,        # type: Optional[DatabaseManager]
                    **kwargs):
        # type: (...) -> BaseHTTPFactory
        """Create a cyclone app around a specific handler_cls for tests.

        Creates an uninitialized (no setup() called) DatabaseManager
        from conf if one isn't specified.

        handler_cls must be included in ap_handlers or a ValueError is
        thrown.

        """
        if 'handlers' in kwargs:  # pragma: nocover
            raise ValueError("handler_cls incompatibile with handlers kwarg")
        for pattern, handler in cls.ap_handlers + cls.health_ap_handlers:
            if handler is handler_cls:
                if db is None:
                    db = DatabaseManager.from_config(conf)
                return cls._for_handler(
                    conf,
                    db=db,
                    handlers=[(pattern, handler)],
                    **kwargs
                )
        raise ValueError("{!r} not in ap_handlers".format(
            handler_cls))  # pragma: nocover

    @classmethod
    def _for_handler(cls, conf, **kwargs):
        # type: (AutopushConfig, **Any) -> BaseHTTPFactory
        """Create an instance w/ default kwargs for for_handler"""
        raise NotImplementedError  # pragma: nocover


class EndpointHTTPFactory(BaseHTTPFactory):

    ap_handlers = (
        (r"/wpush/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
         WebPushHandler),
        (r"/m/(?P<message_id>[^\/]+)", MessageHandler),
        (r"/v1/(?P<type>[^\/]+)/(?P<app_id>[^\/]+)/registration",
         NewRegistrationHandler),
        (r"/v1/(?P<type>[^\/]+)/(?P<app_id>[^\/]+)/registration/"
         r"(?P<uaid>[^\/]+)",
         UaidRegistrationHandler),
        (r"/v1/(?P<type>[^\/]+)/(?P<app_id>[^\/]+)/registration/"
         r"(?P<uaid>[^\/]+)/subscription",
         SubRegistrationHandler),
        (r"/v1/(?P<type>[^\/]+)/(?P<app_id>[^\/]+)/registration/"
         r"(?P<uaid>[^\/]+)/subscription/(?P<chid>[^\/]+)",
         ChannelRegistrationHandler),
        (r"/v1/err(?:/(?P<err_type>[^\/]+))?", LogCheckHandler),
        (r".*", NotFoundHandler),
    )

    protocol = LimitedHTTPConnection

    def __init__(self,
                 conf,         # type: AutopushConfig
                 db,           # type: DatabaseManager
                 routers,      # type: Dict[str, IRouter]
                 **kwargs):
        # type: (...) -> None
        self.ap_handlers = tuple(self.ap_handlers)
        BaseHTTPFactory.__init__(self, conf, db=db, **kwargs)
        self.routers = routers

    def ssl_cf(self):
        # type: () -> Optional[AutopushSSLContextFactory]
        """Build our SSL Factory (if configured).

        Configured from the ssl_key/cert/dh_param and client_cert
        values.

        """
        conf = self.conf
        return conf.ssl.cf(require_peer_certs=conf.enable_tls_auth)

    @classmethod
    def _for_handler(cls, conf, db, routers=None, **kwargs):
        if routers is None:
            routers = routers_from_config(
                conf,
                db=db,
                agent=agent_from_config(conf)
            )
        return cls(conf, db=db, routers=routers, **kwargs)


class InternalRouterHTTPFactory(BaseHTTPFactory):

    ap_handlers = (
        (r"/push/([^\/]+)", RouterHandler),
        (r"/notif/([^\/]+)(?:/(\d+))?", NotificationHandler),
    )

    def __init__(self,
                 conf,         # type: AutopushConfig
                 db,           # type: DatabaseManager
                 clients,      # type: Dict[str, PushServerProtocol]
                 **kwargs):
        # type: (...) -> None
        BaseHTTPFactory.__init__(self, conf, db, **kwargs)
        self.clients = clients

    @property
    def _hostname(self):
        return self.conf.router_hostname

    def ssl_cf(self):
        # type: () -> Optional[AutopushSSLContextFactory]
        """Build our SSL Factory (if configured).

        Configured from the router_ssl_key/cert and ssl_dh_param
        values.

        """
        return self.conf.router_ssl.cf()

    @classmethod
    def _for_handler(cls, conf, db, clients=None, **kwargs):
        if clients is None:
            clients = {}
        return cls(conf, db=db, clients=clients, **kwargs)


class MemUsageHTTPFactory(BaseHTTPFactory):

    ap_handlers = (
        (r"^/_memusage", MemUsageHandler),
    )


class QuietClientFactory(_HTTP11ClientFactory):
    """Silence the start/stop factory messages."""
    noisy = False


def agent_from_config(conf):
    # type: (AutopushConfig) -> Agent
    """Create a twisted.web.client Agent from the given config"""
    # Use a persistent connection pool for HTTP requests.
    pool = HTTPConnectionPool(reactor)
    if not conf.debug:
        pool._factory = QuietClientFactory
    return Agent(reactor, connectTimeout=conf.connect_timeout, pool=pool)
