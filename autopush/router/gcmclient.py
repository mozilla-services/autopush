import json

import requests

from autopush.exceptions import RouterException


class GCMAuthenticationError(Exception):
    pass


class Result(object):
    """Abstraction object for GCM response"""

    def __init__(self, message, response):
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

        self.retry_after = response.headers.get('Retry-After', None)

        if response.status_code != 200:
            self.retry_message = message
        else:
            self._parse_response(message, response.content)

    def _parse_response(self, message, content):
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
            'collapse_key': collapse_key,
            'time_to_live': int(time_to_live),
            'delay_while_idle': False,
            'dry_run': bool(dry_run),
        }
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
        self.log = logger
        self._options = options
        self._sender = requests.post

    def send(self, payload):
        """Send a payload to GCM

        :param payload: Dictionary of GCM formatted data
        :type payload: JSONMessage
        :return: Result

        """
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'key={}'.format(self._api_key),
        }

        response = self._sender(
            url=self._endpoint,
            headers=headers,
            data=json.dumps(payload.payload),
            **self._options
        )

        if response.status_code in (400, 404):
            raise RouterException(response.content)

        if response.status_code == 401:
            raise GCMAuthenticationError("Authentication Error")

        if response.status_code == 200 or (500 <= response.status_code <= 599):
            return Result(payload, response)
