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
