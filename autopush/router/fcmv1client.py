import json

import treq
from oauth2client.service_account import ServiceAccountCredentials
from twisted.logger import Logger
from twisted.internet.error import (ConnectError, TimeoutError)

from autopush.constants import DEFAULT_ROUTER_TIMEOUT
from autopush.exceptions import RouterException


class FCMAuthenticationError(Exception):
    pass


class FCMNotFoundError(Exception):
    pass


class Result(object):

    def __init__(self, response):
        self.code = response.code
        self.success = 0
        self.retry_message = None
        self.retry_after = (
            response.headers.getRawHeaders('Retry-After') or [None])[0]

    def parse_response(self, content):
        # 400 will return an error message indicating what's wrong with the
        #    javascript message you sent.
        # 403 is an error indicating that the client app is missing the
        #    FCM Cloud Messaging permission (and a URL to set it)
        # Successful content body
        #   { "name": "projects/.../messages/0:..."}
        # Failures:
        #   { "error":
        #       { "status": str
        #         "message": str
        #         "code": u64
        #         "details: [
        #             {"errorCode": str,
        #              "@type": str},
        #             {"fieldViolations": [
        #               {"field": str,
        #                "description": str}
        #              ],
        #              "type", str
        #             }
        #          ]
        #      }
        #  }
        # (Failures are a tad more verbose)
        if 500 <= self.code <= 599:
            self.retry_message = content
            return self
        try:
            data = json.loads(content)
            if self.code in (400, 403, 404, 410) or data.get('error'):
                # Having a hard time finding information about how some
                # things are handled in FCM, e.g. retransmit requests.
                # For now, catalog them as errors and provide back-pressure.
                err = data.get("error")
                if err.get("status") == "NOT_FOUND":
                    raise FCMNotFoundError("FCM recipient no longer available")
                raise RouterException("{}: {}".format(err.get("status"),
                                                      err.get("message")))
            if "name" in data:
                self.success = 1
        except (TypeError, ValueError, KeyError, AttributeError):
            raise RouterException(
                "Unknown error response: {}".format(content))
        return self


class FCMv1(object):
    def __init__(self,
                 project_id,
                 service_cred_path=None,
                 logger=None,
                 metrics=None,
                 **options):
        self.project_id = project_id
        self.endpoint = ("https://fcm.googleapis.com/v1/"
                         "projects/{}/messages:send".format(self.project_id))

        self.token = None
        self.metrics = metrics
        self.logger = logger or Logger()
        self._options = options
        if service_cred_path:
            self.svc_cred = ServiceAccountCredentials.from_json_keyfile_name(
                service_cred_path,
                ["https://www.googleapis.com/auth/firebase.messaging"])
        self._sender = treq.post

    def _get_access_token(self):
        return self.svc_cred.get_access_token()

    def _build_message(self, token, notif):
        msg = {
            "token": token,
            # Specify the various formats (we use android only)
            "android": {
                # TTL is a duration string e.g. ("60s")
                "ttl": str(int(notif.get("ttl", 0)))+"s",
                "data": notif.get("data_message")
            },
        }
        # Wrap up the whole thing in a "message" tag.
        return {"message": msg}

    def process(self, response, payload=None):
        if response.code == 401:
            raise FCMAuthenticationError("Authentication Error")

        result = Result(response)

        d = response.text()
        d.addCallback(result.parse_response)
        return d

    def error(self, failure):
        if isinstance(failure.value,
                      (FCMAuthenticationError, FCMNotFoundError,
                       TimeoutError, ConnectError)):
            raise failure.value
        self.logger.error("FCMv1Client failure: {}".format(failure.value))
        raise RouterException("Server error: {}".format(failure.value))

    def send(self, token, payload):
        atoken = self._get_access_token()
        headers = {
            'Authorization': 'Bearer {}'.format(atoken.access_token),
            'Content-Type': 'application/json; UTF-8'
        }
        message = self._build_message(token, payload)
        if 'timeout' not in self._options:
            self._options['timeout'] = DEFAULT_ROUTER_TIMEOUT

        d = self._sender(
            url=self.endpoint,
            headers=headers,
            data=json.dumps(message),
            **self._options
        )
        d.addCallback(self.process, payload)
        d.addErrback(self.error)
        return d
