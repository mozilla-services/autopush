import json

import treq
from twisted.web.http_headers import Headers
from twisted.logger import Logger
from twisted.internet.error import ConnectError

from autopush.constants import DEFAULT_ROUTER_TIMEOUT
from autopush.exceptions import RouterException


class GCMAuthenticationError(Exception):
    pass


class Result(object):
    """Abstraction object for GCM response"""

    def __init__(self, response, message):
        """Process GCM message and response into abstracted object

        :param message: Message payload
        :type message: JSONMessage
        :param response: GCM response
        :type response: requests.Response

        """
        self.success = {}
        self.canonicals = {}
        self.unavailable = []
        self.not_registered = []
        self.failed = {}

        self.message = message
        self.retry_message = None

        self.retry_after = (
            response.headers.getRawHeaders('Retry-After') or [None])[0]

    def parse_response(self, content, code, message):
        # 401 handled in GCM.process()
        if code in (400, 404):
            raise RouterException(content)
        data = json.loads(content)
        if not data.get('results'):
            raise RouterException("Recv'd invalid response from GCM")
        reg_id = message.payload['registration_ids'][0]
        for res in data['results']:
            if 'message_id' in res:
                self.success[reg_id] = res['message_id']
                if 'registration_id' in res:
                    self.canonicals[reg_id] = res['registration_id']
            else:
                if res['error'] in ['Unavailable', 'InternalServerError']:
                    self.unavailable.append(reg_id)
                elif res['error'] == 'NotRegistered':
                    self.not_registered.append(reg_id)
                else:
                    self.failed[reg_id] = res['error']
        return self


class JSONMessage(object):
    """GCM formatted payload

    """
    def __init__(self,
                 registration_ids,
                 collapse_key,
                 time_to_live,
                 dry_run,
                 data):
        """Convert data elements into a GCM payload.

        :param registration_ids: Single or list of registration ids to send to
        :type registration_ids: str or list
        :param collapse_key: GCM collapse key for the data.
        :type collapse_key: str
        :param time_to_live: Seconds to keep message alive
        :type time_to_live: int
        :param dry_run: GCM Dry run flag to allow remote verification
        :type dry_run: bool
        :param data: Data elements to send
        :type data: dict

        """
        if not registration_ids:
            raise RouterException("No Registration IDs specified")
        if not isinstance(registration_ids, list):
            registration_ids = [registration_ids]
        self.registration_ids = registration_ids
        self.payload = {
            'registration_ids': self.registration_ids,
            'time_to_live': int(time_to_live),
            'delay_while_idle': False,
            'dry_run': bool(dry_run),
        }
        if collapse_key:
            self.payload["collapse_key"] = collapse_key
        if data:
            self.payload['data'] = data


class GCM(object):
    """Primitive HTTP GCM service handler."""

    def __init__(self,
                 api_key=None,
                 logger=None,
                 metrics=None,
                 endpoint="gcm-http.googleapis.com/gcm/send",
                 **options):

        """Initialize the GCM primitive.

        :param api_key: The GCM API key (from the Google developer console)
        :type api_key: str
        :param logger: Status logger
        :type logger: logger
        :param metrics: Metric recorder
        :type metrics: autopush.metrics.IMetric
        :param endpoint: GCM endpoint override
        :type endpoint: str
        :param options: Additional options
        :type options: dict

        """
        self._endpoint = "https://{}".format(endpoint)
        self._api_key = api_key
        self.metrics = metrics
        self.log = logger or Logger()
        self._options = options
        self._sender = treq.post

    def process(self, response, payload):
        if response.code == 401:
            raise GCMAuthenticationError("Authentication Error")

        result = Result(response, payload)

        if 500 <= response.code <= 599:
            result.retry_message = payload
            return result

        # Fetch the content body
        d = response.text()
        d.addCallback(result.parse_response, response.code, payload)
        return d

    def error(self, failure):
        if isinstance(failure.value, GCMAuthenticationError) or \
                isinstance(failure.value, ConnectError):
            raise failure.value
        self.log.error("GCMClient failure: {}".format(failure.value))
        raise RouterException("Server error: {}".format(failure.value))

    def send(self, payload):
        """Send a payload to GCM

        :param payload: Dictionary of GCM formatted data
        :type payload: JSONMessage
        :return: Result

        """
        headers = Headers({
            'Content-Type': ['application/json'],
            'Authorization': ['key={}'.format(self._api_key)],
        })

        if 'timeout' not in self._options:
            self._options['timeout'] = DEFAULT_ROUTER_TIMEOUT

        d = self._sender(
            url=self._endpoint,
            headers=headers,
            data=json.dumps(payload.payload),
            **self._options
        )
        # handle the immediate response (which contains no body)
        d.addCallback(self.process, payload)
        d.addErrback(self.error)
        return d
