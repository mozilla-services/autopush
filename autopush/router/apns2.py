import json
from collections import deque

import hyper.tls
from hyper import HTTP20Connection
from hyper.http20.exceptions import HTTP20Error

from autopush.router.interface import RouterException

SANDBOX = 'api.development.push.apple.com'
SERVER = 'api.push.apple.com'

APNS_PRIORITY_IMMEDIATE = 10
APNS_PRIORITY_LOW = 5
APNS_MAX_CONNECTIONS = 20


class APNSException(Exception):
    pass


class APNSClient(object):
    def __init__(self, cert_file, key_file, topic,
                 alt=False, use_sandbox=False,
                 max_connections=APNS_MAX_CONNECTIONS,
                 logger=None, metrics=None):
        """Create the APNS client connector.

        The cert_file and key_file can be derived from the exported `.p12`
        **Apple Push Services: *bundleID*** key contained in the **Keychain
        Access** application. To extract the proper PEM formatted data, you
        can use the following commands:

        ```
        openssl pkcs12 -in file.p12 -out apns_cert.pem -clcerts -nokeys
        openssl pkcs12 -in file.p12 -out apns_key.pem -nocerts -nodes
        ```

        The *topic* is the Bundle ID of the bridge recipient iOS application.
        Since the cert needs to be tied directly to an application, the topic
        is usually similar to "com.example.MyApplication".

        :param cert_file: Path to the PEM formatted APNs certification file.
        :type cert_file: str
        :param key_file: Path to the PEM formatted APNs key file.
        :type key_file: str
        :param topic: The *Bundle ID* that identifies the assoc. iOS app.
        :type topic: str
        :param alt: Use the alternate APNs publication port (if 443 is blocked)
        :type alt: bool
        :param use_sandbox: Use the development sandbox
        :type use_sandbox: bool
        :param max_connections: Max number of pooled connections to use
        :type max_connections: int
        :param logger: Status logger
        :type logger: logger
        :param metrics: Metric recorder
        :type metrics: autopush.metrics.IMetric
        """
        self.server = SANDBOX if use_sandbox else SERVER
        self.port = 2197 if alt else 443
        self.ssl_context = hyper.tls.init_context(cert=(cert_file, key_file))
        self.log = logger
        self.metrics = metrics
        self.topic = topic
        self._max_connections = max_connections
        self.connections = deque(maxlen=max_connections)
        if self.log:
            self.log.info("Starting APNS connection")

        self.connections.extendleft((HTTP20Connection(
            self.server,
            self.port,
            ssl_context=self.ssl_context,
            force_proto='h2') for x in range(0, max_connections)))

    def send(self, router_token, payload, apns_id,
             priority=True, topic=None, exp=None):
        """Send the dict of values to the remote bridge

        This sends the raw data to the remote bridge application using the
        APNS2 HTTP2 API.

        :param router_token: APNs provided hex token identifying recipient
        :type router_token: str
        :param payload: Data to send to recipient
        :type payload: dict
        :param priority: True is high priority, false is low priority
        :type priority: bool
        :param topic: BundleID for the recipient application (overides default)
        :type topic: str
        :param exp: Message expiration timestamp
        :type exp: timestamp

        """
        body = json.dumps(payload)
        priority = APNS_PRIORITY_IMMEDIATE if priority else APNS_PRIORITY_LOW
        headers = {
            'apns-id': apns_id,
            'apns-priority': priority,
            'apns-topic': topic or self.topic,
        }
        if exp:
            headers['apns-expiration'] = exp
        url = '/3/device/' + router_token
        connection = self._get_connection()
        try:
            # request auto-opens closed connections, so if a connection
            # has timed out or failed for other reasons, it's automatically
            # re-established.
            stream_id = connection.request(
                'POST', url=url, body=body, headers=headers)
            response = connection.get_response(stream_id)
            if response.status != 200:
                reason = json.loads(response.read().decode('utf-8'))['reason']
                raise RouterException(
                    "APNS Transmit Error {}:{}".format(response.status,
                                                       reason),
                    status_code=500,
                    response_body="APNS could not process "
                                  "your message {}".format(reason))
        except HTTP20Error as ex:
            connection.close()
            raise RouterException(
                "APNS Processing error: {}".format(repr(ex)),
                status_code=503,
                response_body="APNS returned an error processing request",
            )
        finally:
            # Returning a closed connection to the pool is ok.
            # hyper will reconnect on .request()
            self._return_connection(connection)

    def _get_connection(self):
        try:
            connection = self.connections.pop()
            return connection
        except IndexError:
            raise RouterException(
                "Too many APNS requests, increase pool from {}".format(
                    self._max_connections
                ),
                status_code=503,
                response_body="APNS busy, please retry")

    def _return_connection(self, connection):
        self.connections.appendleft(connection)
