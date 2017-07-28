import sys
import uuid
from typing import TYPE_CHECKING

import cyclone.web
from twisted.logger import Logger
from twisted.python import failure

if TYPE_CHECKING:  # pragma: nocover
    from autopush.db import DatabaseManager  # noqa
    from autopush.metrics import IMetrics  # noqa
    from autopush.settings import AutopushConfig  # noqa


class BaseHandler(cyclone.web.RequestHandler):
    """Base cyclone RequestHandler for autopush"""

    log = Logger()

    def initialize(self):
        """Initialize info from the client"""
        self._client_info = self._init_info()

    @property
    def ap_settings(self):
        # type: () -> AutopushConfig
        return self.application.ap_settings

    @property
    def db(self):
        # type: () -> DatabaseManager
        return self.application.db

    @property
    def metrics(self):
        # type: () -> IMetrics
        return self.db.metrics

    def _init_info(self):
        return dict(
            ami_id=self.ap_settings.ami_id,
            request_id=str(uuid.uuid4()),
            user_agent=self.request.headers.get('user-agent', ""),
            remote_ip=self.request.headers.get('x-forwarded-for',
                                               self.request.remote_ip),
            authorization=self.request.headers.get('authorization', ""),
            message_ttl=self.request.headers.get('ttl', None),
            uri=self.request.uri,
            python_version=sys.version,
        )

    def write_error(self, code, **kwargs):
        """Write the error (otherwise unhandled exception when dealing with
        unknown method specifications.)

        This is a Cyclone API Override method used by endpoint and
        websocket.

        """
        self.set_status(code)
        if 'exc_info' in kwargs:
            self.log.failure(
                format=kwargs.get('format', "Exception"),
                failure=failure.Failure(*kwargs['exc_info']),
                client_info=self._client_info)
        else:
            self.log.failure("Error in handler: %s" % code,
                             client_info=self._client_info)
        self.finish()

    def authenticate_peer_cert(self):
        """Authenticate the client per the configured client_certs.

        Aborts the request w/ a 401 on failure.

        """
        cert = self.request.connection.transport.getPeerCertificate()
        if cert:
            cert_signature = cert.digest('sha256')
            cn = cert.get_subject().CN
            auth = self.ap_settings.client_certs.get(cert_signature)
            if auth is not None:
                # TLS authenticated
                self._client_info.update(tls_auth=auth,
                                         tls_auth_sha256=cert_signature,
                                         tls_auth_cn=cn)
                return

            self._client_info.update(tls_failed_sha256=cert_signature,
                                     tls_failed_cn=cn)

        self.log.warn("Failed TLS auth", client_info=self._client_info)
        self.set_status(401)
        # "Transport mode" isn't standard, inspired by:
        # http://www6.ietf.org/mail-archive/web/tls/current/msg05589.html
        self.set_header('WWW-Authenticate',
                        'Transport mode="tls-client-certificate"')
        self.finish()
