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
