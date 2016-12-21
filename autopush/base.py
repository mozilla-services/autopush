import json
import uuid

import cyclone.web
from twisted.logger import Logger
from twisted.python import failure

status_codes = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    413: "Payload Too Large",
    418: "I'm a teapot",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
DEFAULT_ERR_URL = ("http://autopush.readthedocs.io/en/latest/http.html"
                   "#error-codes")


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
        """Authenticate the client per the configured client_certs.

        Aborts the request w/ a 401 on failure.

        """
        cert = self.request.connection.transport.getPeerCertificate()
        # VERIFY_FAIL_IF_NO_PEER_CERT ensures this never fails
        # otherwise something is very broken
        assert cert, "Expected a TLS peer cert (VERIFY_FAIL_IF_NO_PEER_CERT)"

        cert_signature = cert.digest('sha256')
        cn = cert.get_subject().CN
        auth = self.ap_settings.client_certs.get(cert_signature)
        if auth is not None:
            # TLS authenticated
            self._client_info['tls_auth'] = auth
            self._client_info['tls_auth_sha256'] = cert_signature
            self._client_info['tls_auth_cn'] = cn
            return

        self.log.warn("Failed TLS auth",
                      tls_failed_sha256=cert_signature,
                      tls_failed_cn=cn,
                      client_info=self._client_info)
        self.set_status(401)
        # "Transport mode" isn't standard, inspired by:
        # http://www6.ietf.org/mail-archive/web/tls/current/msg05589.html
        self.set_header('WWW-Authenticate',
                        'Transport mode="tls-client-certificate"')
        self.finish()

    def _write_response(self, status_code, errno=None, message=None,
                        error=None, headers=None, url=DEFAULT_ERR_URL):
        """Writes out a full JSON error and sets the appropriate status"""
        self.set_status(status_code, reason=error)
        error_data = dict(
            code=status_code,
            error=error or status_codes.get(status_code, ""),
            more_info=url,
        )
        if errno:
            error_data["errno"] = errno
        if message:
            error_data["message"] = message
        self.write(json.dumps(error_data))
        self.set_header("Content-Type", "application/json")
        if headers:
            for header in headers.keys():
                self.set_header(header, headers.get(header))
        self.finish()


class DefaultHandler(BaseHandler):
    """Unauthenticated catch-all handler that returns a 404 for
    unknown paths. Cyclone matches handlers in order, so this handler
    should be registered last."""

    def authenticate_peer_cert(self):
        pass

    def prepare(self):
        self._write_response(404)
