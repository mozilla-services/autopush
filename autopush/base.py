import uuid

import cyclone.web
from twisted.logger import Logger
from twisted.python import failure


class BaseHandler(cyclone.web.RequestHandler):
    """Base cyclone RequestHandler for autopush"""

    log = Logger()

    def initialize(self, ap_settings):
        """Setup basic attributes from AutopushSettings"""
        self.ap_settings = ap_settings
        self._client_info = self._init_info()

    def _init_info(self):
        return dict(
            ami_id=self.ap_settings.ami_id,
            request_id=str(uuid.uuid4()),
            user_agent=self.request.headers.get('user-agent', ""),
            remote_ip=self.request.headers.get('x-forwarded-for',
                                               self.request.remote_ip),
            authorization=self.request.headers.get('authorization', ""),
            message_ttl=self.request.headers.get('ttl', ""),
            uri=self.request.uri,
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
        """Authenticate the client per the configured peer certs.

        Aborts the request w/ a 401 on failure.

        """
        cert = self.request.connection.transport.getPeerCertificate()
        if cert:
            sha256 = cert.digest('sha256')
            auth = self.ap_settings.client_certs.get(sha256)
            if auth is not None:
                # TLS authenticated
                self._client_info['tls_auth'] = auth
                self._client_info['tls_auth_cn'] = cert.get_subject().CN
                # XXX: metrics
                return

        # XXX: something should probably be different if the error is cert=None..
        # auth failed
        # XXX: logging, metrics
        self.set_status(401)
        # "Transport mode" isn't standard, inspired by:
        # http://www6.ietf.org/mail-archive/web/tls/current/msg05589.html
        self.set_header('WWW-Authenticate',
                        'Transport mode="tls-client-certificate"')
        self.finish()
