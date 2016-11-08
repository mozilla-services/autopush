"""Autopush Exceptions"""


class AutopushException(Exception):
    """Parent Autopush Exception"""


class InvalidTokenException(Exception):
    """Invalid URL token Exception"""


class InvalidRequest(AutopushException):
    """Invalid request exception, may include custom status_code and message
    to write for the error"""
    def __init__(self, message, status_code=400, errno=None, headers=None):
        super(AutopushException, self).__init__(message)
        self.status_code = status_code
        self.errno = errno
        self.headers = {} if headers is None else headers


class VapidAuthException(Exception):
    """Exception if the VAPID Auth token fails"""
    pass


class MissingTableException(Exception):
    """Exception for missing tables"""
    pass


class APNSException(Exception):
    pass


class MessageOverloadException(Exception):
    """Too many messages per UAID"""
    pass


class RouterException(AutopushException):
    """Exception if routing has failed, may include a custom status_code and
    body to write to the response.

    """
    def __init__(self, message, status_code=500, response_body="",
                 router_data=None, headers=None, log_exception=True,
                 errno=None, logged_status=None, **kwargs):
        """Create a new RouterException"""
        super(AutopushException, self).__init__(message)
        self.status_code = status_code
        self.headers = {} if headers is None else headers
        self.log_exception = log_exception
        self.response_body = response_body or message
        self.errno = errno
        self.logged_status = logged_status
        self.extra = kwargs


class LogCheckError(Exception):
    """Exception raised on purpose to check logging functions"""
    pass
