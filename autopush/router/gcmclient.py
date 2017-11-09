import json

import requests

from autopush.exceptions import RouterException


class GCMAuthenticationError(Exception):
    pass


class Result(object):

    def __init__(self, message, response):
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

    def __init__(self,
                 registration_ids,
                 collapse_key,
                 time_to_live,
                 dry_run,
                 data):
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

    def __init__(self,
                 api_key=None,
                 logger=None,
                 metrics=None,
                 endpoint="gcm-http.googleapis.com/gcm/send",
                 **options):

        self._endpoint = "https://{}".format(endpoint)
        self._api_key = api_key
        self.metrics = metrics
        self.log = logger
        self._options = options
        self._sender = requests.post

    def send(self, payload):
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
