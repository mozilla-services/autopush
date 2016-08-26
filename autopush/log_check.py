import cyclone.web

from autopush.endpoint import AutoendpointHandler


class LogCheckError(Exception):
    pass


class LogCheckHandler(AutoendpointHandler):

    def initialize(self, ap_settings):
        self.ap_settings = ap_settings
        self._client_info = self._init_info()

    @cyclone.web.asynchronous
    def get(self, err_type=None):
        """HTTP GET

        Generate a dummy error message for logging

        """
        if not err_type:
            err_type = "error"
        else:
            err_type = err_type.lower()
        if 'error' in err_type:
            self.log.error(format="Test Error Message",
                           status_code=418, errno=0,
                           **self._client_info)
            self._write_response(418, 999, message="ERROR:Success",
                                 reason="Test Error")
        if 'crit' in err_type:
            try:
                raise LogCheckError("LogCheck")
            except LogCheckError:
                self.log.failure(format="Test Critical Message",
                                 status_code=418, errno=0,
                                 **self._client_info)
                self._write_response(418, 999, message="FAILURE:Success",
                                     reason="Test Failure")
