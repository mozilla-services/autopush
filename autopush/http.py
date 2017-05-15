"""HTTP Server Protocol Factories on top of cyclone"""
from typing import (  # noqa
    Any,
    Callable,
    Optional,
    Sequence,
    Tuple,
    Type
)

import cyclone.web

from autopush.base import BaseHandler
from autopush.settings import AutopushSettings  # noqa
from autopush.ssl import AutopushSSLContextFactory
from autopush.web.health import (
    HealthHandler,
    MemUsageHandler,
    StatusHandler
)
from autopush.web.limitedhttpconnection import LimitedHTTPConnection
from autopush.web.log_check import LogCheckHandler
from autopush.web.message import MessageHandler
from autopush.web.registration import RegistrationHandler
from autopush.web.simplepush import SimplePushHandler
from autopush.web.webpush import WebPushHandler
from autopush.websocket import (
    NotificationHandler,
    RouterHandler,
)

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
    )

    def __init__(self,
                 ap_settings,
                 handlers=None,
                 log_function=skip_request_logging,
                 **kwargs):
        # type: (AutopushSettings, APHandlers, CycloneLogger, **Any) -> None
        self.ap_settings = ap_settings
        self.noisy = ap_settings.debug

        cyclone.web.Application.__init__(
            self,
            default_host=self._hostname,
            debug=ap_settings.debug,
            log_function=log_function,
            **kwargs
        )
        self.add_ap_handlers(
            self.ap_handlers if handlers is None else handlers)

    def add_ap_handlers(self, handlers):
        # type: (APHandlers) -> None
        """Add BaseHandlers w/ their appropriate handler kwargs"""
        h_kwargs = dict(ap_settings=self.ap_settings)
        self.add_handlers(
            ".*$",
            [(pattern, handler, h_kwargs) for pattern, handler in handlers]
        )

    def add_health_handlers(self):
        """Add the health check HTTP handlers"""
        self.add_ap_handlers(self.health_ap_handlers)

    @property
    def _hostname(self):
        return self.ap_settings.hostname

    @classmethod
    def for_handler(cls, handler_cls, *args, **kwargs):
        # type: (Type[BaseHandler], *Any, **Any) -> BaseHTTPFactory
        """Create a cyclone app around a specific handler_cls.

        handler_cls must be included in ap_handlers or a ValueError is
        thrown.

        """
        for pattern, handler in cls.ap_handlers:
            if handler is handler_cls:
                return cls(handlers=[(pattern, handler)], *args, **kwargs)
        raise ValueError("{!r} not in ap_handlers".format(
            handler_cls))  # pragma: nocover


class EndpointHTTPFactory(BaseHTTPFactory):

    ap_handlers = (
        (r"/spush/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
         SimplePushHandler),
        (r"/wpush/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)",
         WebPushHandler),
        (r"/m/(?P<message_id>[^\/]+)", MessageHandler),
        (r"/v1/(?P<router_type>[^\/]+)/(?P<router_token>[^\/]+)/"
         r"registration(?:/(?P<uaid>[^\/]+))?(?:/subscription)?"
         r"(?:/(?P<chid>[^\/]+))?", RegistrationHandler),
        (r"/v1/err(?:/(?P<err_type>[^\/]+))?", LogCheckHandler),
    )

    protocol = LimitedHTTPConnection

    def ssl_cf(self):
        # type: () -> Optional[AutopushSSLContextFactory]
        """Build our SSL Factory (if configured).

        Configured from the ssl_key/cert/dh_param and client_cert
        values.

        """
        settings = self.ap_settings
        if not settings.ssl_key:
            return None
        return AutopushSSLContextFactory(
            settings.ssl_key,
            settings.ssl_cert,
            dh_file=settings.ssl_dh_param,
            require_peer_certs=settings.enable_tls_auth
        )


class InternalRouterHTTPFactory(BaseHTTPFactory):

    ap_handlers = (
        (r"/push/([^\/]+)", RouterHandler),
        (r"/notif/([^\/]+)(/([^\/]+))?", NotificationHandler),
    )

    @property
    def _hostname(self):
        return self.ap_settings.router_hostname

    def ssl_cf(self):
        # type: () -> Optional[AutopushSSLContextFactory]
        """Build our SSL Factory (if configured).

        Configured from the router_ssl_key/cert and ssl_dh_param
        values.

        """
        settings = self.ap_settings
        if not settings.router_ssl_key:
            return None
        return AutopushSSLContextFactory(
            settings.router_ssl_key,
            settings.router_ssl_cert,
            dh_file=settings.ssl_dh_param
        )


class MemUsageHTTPFactory(BaseHTTPFactory):

    ap_handlers = (
        (r"^/_memusage", MemUsageHandler),
    )
