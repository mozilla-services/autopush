from marshmallow import Schema, fields, pre_load
from typing import Optional  # noqa

from autopush.exceptions import LogCheckError
from autopush.web.base import threaded_validate, BaseWebHandler


class LogCheckSchema(Schema):
    """Empty schema for log check"""
    err_type = fields.Str(allow_none=True)

    @pre_load
    def extract_data(self, req):
        return dict(err_type=req['path_kwargs'].get('err_type'))


class LogCheckHandler(BaseWebHandler):

    def authenticate_peer_cert(self):
        """LogCheck skips authentication checks"""
        pass

    @threaded_validate(LogCheckSchema)
    def get(self, err_type=None):
        # type: (Optional[str]) -> None
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
                           client_info=self._client_info)
            self._write_response(418, 999, message="ERROR:Success",
                                 error="Test Error")
        elif 'crit' in err_type:
            try:
                raise LogCheckError("LogCheck")
            except LogCheckError:
                self.log.failure(format="Test Critical Message",
                                 status_code=418, errno=0,
                                 client_info=self._client_info)
                self._write_response(418, 999, message="FAILURE:Success",
                                     error="Test Failure")
        else:
            self._write_response(404, 0)
