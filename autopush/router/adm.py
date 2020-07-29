"""ADM Router"""
import time
import requests

from typing import Any  # noqa

from requests.exceptions import ConnectionError, Timeout
from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from autopush.constants import DEFAULT_ROUTER_TIMEOUT
from autopush.exceptions import RouterException
from autopush.metrics import make_tags
from autopush.router.interface import RouterResponse
from autopush.types import JSONDict  # noqa


class ADMAuthError(Exception):
    pass


class ADMClient(object):
    def __init__(self,
                 credentials=None,
                 logger=None,
                 metrics=None,
                 endpoint="api.amazon.com",
                 timeout=DEFAULT_ROUTER_TIMEOUT,
                 **options
                 ):

        self._client_id = credentials["client_id"]
        self._client_secret = credentials["client_secret"]
        self._token_exp = 0
        self._auth_token = None
        self._aws_host = endpoint
        self._logger = logger
        self._metrics = metrics
        self._request = requests
        self._timeout = timeout

    def refresh_key(self):
        url = "https://{}/auth/O2/token".format(self._aws_host)
        if self._auth_token is None or self._token_exp < time.time():
            body = dict(
                grant_type="client_credentials",
                scope="messaging:push",
                client_id=self._client_id,
                client_secret=self._client_secret
            )
            headers = {
                "content-type": "application/x-www-form-urlencoded"
            }
            resp = self._request.post(url, data=body, headers=headers,
                                      timeout=self._timeout)
            if resp.status_code != 200:
                self._logger.error("Could not get ADM Auth token {}".format(
                    resp.text
                ))
                raise ADMAuthError("Could not fetch auth token")
            reply = resp.json()
            self._auth_token = reply['access_token']
            self._token_exp = time.time() + reply.get('expires_in', 0)

    def send(self, reg_id, payload, ttl=None, collapseKey=None):
        self.refresh_key()
        headers = {
            "Authorization": "Bearer {}".format(self._auth_token),
            "Content-Type": "application/json",
            "X-Amzn-Type-Version":
                "com.amazon.device.messaging.ADMMessage@1.0",
            "X-Amzn-Accept-Type":
                "com.amazon.device.messaging.ADMSendResult@1.0",
            "Accept": "application/json",
        }
        data = {}
        if ttl:
            data["expiresAfter"] = ttl
        if collapseKey:
            data["consolidationKey"] = collapseKey
        data["data"] = payload
        url = ("https://api.amazon.com/messaging/registrations"
               "/{}/messages".format(reg_id))
        resp = self._request.post(
            url,
            json=data,
            headers=headers,
            timeout=self._timeout,
        )
        # in fine tradition, the response message can sometimes be less than
        # helpful. Still, good idea to include it anyway.
        if resp.status_code != 200:
            self._logger.error("Could not send ADM message: " + resp.text)
            raise RouterException(resp.content)


class ADMRouter(object):
    """Amazon Device Messaging Router Implementation"""
    log = Logger()
    dryRun = 0
    collapseKey = None
    MAX_TTL = 2419200

    def __init__(self, conf, router_conf, metrics):
        """Create a new ADM router and connect to ADM"""
        self.conf = conf
        self.router_conf = router_conf
        self.metrics = metrics
        self.min_ttl = router_conf.get("ttl", 60)
        timeout = router_conf.get("timeout", DEFAULT_ROUTER_TIMEOUT)
        self.profiles = dict()
        for profile in router_conf:
            config = router_conf[profile]
            if "client_id" not in config or "client_secret" not in config:
                raise IOError("Profile info incomplete, missing id or secret")
            self.profiles[profile] = ADMClient(
                credentials=config,
                logger=self.log,
                metrics=self.metrics,
                timeout=timeout)
        self._base_tags = ["platform:adm"]
        self.log.debug("Starting ADM router...")

    def amend_endpoint_response(self, response, router_data):
        # type: (JSONDict, JSONDict) -> None
        pass

    def register(self, uaid, router_data, app_id, *args, **kwargs):
        # type: (str, JSONDict, str, *Any, **Any) -> None
        """Validate that the ADM Registration ID is in the ``router_data``"""
        if "token" not in router_data:
            raise self._error("connect info missing ADM Instance 'token'",
                              status=401)
        profile_id = app_id
        if profile_id not in self.profiles:
            raise self._error("Invalid ADM Profile",
                              status=410, errno=105,
                              uri=kwargs.get('uri'),
                              profile_id=profile_id)
        # Assign a profile
        router_data["creds"] = {"profile": profile_id}

    def route_notification(self, notification, uaid_data):
        """Start the ADM notification routing, returns a deferred"""
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, uaid_data)

    def _route(self, notification, uaid_data):
        """Blocking ADM call to route the notification"""
        router_data = uaid_data["router_data"]
        # THIS MUST MATCH THE CHANNELID GENERATED BY THE REGISTRATION SERVICE
        # Currently this value is in hex form.
        data = {"chid": notification.channel_id.hex}
        # Payload data is optional. The endpoint handler validates that the
        # correct encryption headers are included with the data.
        if notification.data:
            data['body'] = notification.data
            data['con'] = notification.headers['encoding']

            if 'encryption' in notification.headers:
                data['enc'] = notification.headers.get('encryption')
            if 'crypto_key' in notification.headers:
                data['cryptokey'] = notification.headers['crypto_key']

        # registration_ids are the ADM instance tokens (specified during
        # registration.
        ttl = min(self.MAX_TTL,
                  max(notification.ttl or 0, self.min_ttl))

        try:
            adm = self.profiles[router_data['creds']['profile']]
            adm.send(
                reg_id=router_data.get("token"),
                payload=data,
                collapseKey=notification.topic,
                ttl=ttl
            )
        except RouterException:
            raise  # pragma nocover
        except Timeout as e:
            self.log.warn("ADM Timeout: %s" % e)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="timeout"))
            raise RouterException("Server error", status_code=502,
                                  errno=902,
                                  log_exception=False)
        except ConnectionError as e:
            self.log.warn("ADM Unavailable: %s" % e)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="connection unavailable"))
            raise RouterException("Server error", status_code=502,
                                  errno=902,
                                  log_exception=False)
        except ADMAuthError as e:
            self.log.error("ADM unable to authorize: %s" % e)
            self.metrics.increment("notification.bridge.error",
                                   tags=make_tags(
                                       self._base_tags,
                                       reason="auth failure"
                                   ))
            raise RouterException("Server error", status_code=502,
                                  errno=901,
                                  log_exception=False)
        except Exception as e:
            self.log.error("Unhandled exception in ADM Routing: %s" % e)
            raise RouterException("Server error", status_code=500)
        location = "%s/m/%s" % (self.conf.endpoint_url, notification.version)
        return RouterResponse(status_code=201, response_body="",
                              headers={"TTL": ttl,
                                       "Location": location},
                              logged_status=200)

    def _error(self, err, status, **kwargs):
        """Error handler that raises the RouterException"""
        self.log.debug(err, **kwargs)
        return RouterException(err, status_code=status, response_body=err,
                               **kwargs)
