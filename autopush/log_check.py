import uuid

import cyclone.web

from autopush.endpoint import AutoendpointHandler


class LogCheckError(Exception):
    pass


class LogCheckHandler(AutoendpointHandler):

    def initialize(self, ap_settings):
        self.ap_settings = ap_settings
        self.request_id = str(uuid.uuid4())
        self._client_info = self._init_info()

    @cyclone.web.asynchronous
    def get(self, errType=None):
        """HTTP GET

        Generate a dummy error message for logging

        """
        if not errType:
            errType = "error"
        else:
            errType = errType.lower()
        if 'error' in errType:
            self.log.error(format="Test Error Message",
                           status_code=418, errno=0,
                           **self._client_info)
            self._write_response(418, 999, message="ERROR:Success",
                                 reason="Test Error")
        if 'crit' in errType:
            try:
                raise LogCheckError("LogCheck")
            except:
                self.log.failure(format="Test Critical Message",
                                 status_code=418, errno=0,
                                 **self._client_info)
                self._write_response(418, 999, message="FAILURE:Success",
                                     reason="Test Failure")
