import json
from collections import deque
from decimal import Decimal
import time

import threading

import hyper.tls
from hyper import HTTP20Connection
from hyper.http20.exceptions import HTTP20Error

from autopush.exceptions import RouterException


SANDBOX = 'api.development.push.apple.com'
SERVER = 'api.push.apple.com'

APNS_MAX_CONNECTIONS = 20

# These values are defined by APNs as header values that should be sent.
# The hyper library requires that all header values be strings.
# These values should be considered "opaque" to APNs.
# see https://developer.apple.com/search/?q=%22apns-priority%22
APNS_PRIORITY_IMMEDIATE = '10'
APNS_PRIORITY_LOW = '5'


class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj.to_integral_value())
        # for most data types, this function isn't called.
        # the following is added for safety, but should not
        # be required.
        return json.JSONEncoder.default(self, obj)  # pragma nocover


class APNSException(Exception):
    pass


class APNSConnection:
    def __init__(self, conn):
        self._conn = conn
        self._last_used = time.time()


class APNSClient(object):
    def __init__(self, cert_file, key_file, topic,
                 alt=False, use_sandbox=False,
                 max_connections=APNS_MAX_CONNECTIONS,
                 logger=None, metrics=None,
                 load_connections=True,
                 max_retry=2,
                 conn_ttl=30,
                 reap_sleep=60):
        """Create the APNS client connector.

        The cert_file and key_file can be derived from the exported `.p12`
        **Apple Push Services: *bundleID* ** key contained in the **Keychain
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
        :param load_connections: used for testing
        :type load_connections: bool
        :param max_retry: Number of HTTP2 transmit attempts
        :type max_retry: int

        """
        self.server = SANDBOX if use_sandbox else SERVER
        self.port = 2197 if alt else 443
        self.log = logger
        self.metrics = metrics
        self.topic = topic
        self._in_use_connections = 0
        self._max_connections = max_connections
        self._max_retry = max_retry
        self._max_conn_ttl = conn_ttl
        self.connections = deque(maxlen=max_connections)
        if load_connections:
            self.ssl_context = hyper.tls.init_context(cert=(cert_file,
                                                            key_file))
        if self.log:
            self.log.debug("Starting APNS connection")
        self._reap_sleep = reap_sleep
        # this is probably wrong.
        self._reaper = threading.Thread(target=self._reap, args=())
        self._reaper.daemon = True
        self._reaper.start()

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
        body = json.dumps(payload, cls=ComplexEncoder)
        priority = APNS_PRIORITY_IMMEDIATE if priority else APNS_PRIORITY_LOW
        # NOTE: Hyper requires that all header values be strings. 'Priority'
        # is a integer string, which may be "simplified" and cause an error.
        # The added str() function safeguards against that.
        headers = {
            'apns-id': apns_id,
            'apns-priority': str(priority),
            'apns-topic': topic or self.topic,
        }
        if exp:
            headers['apns-expiration'] = str(exp)
        url = '/3/device/' + router_token
        attempt = 0
        while True:
            try:
                connection = self._get_connection()
                # request auto-opens closed connections, so if a connection
                # has timed out or failed for other reasons, it's automatically
                # re-established.
                stream_id = connection.request(
                    'POST', url=url, body=body, headers=headers)
                # get_response() may return an AttributeError. Not really sure
                # how it happens, but the connected socket may get set to None.
                # We'll treat that as a premature socket closure.
                response = connection.get_response(stream_id)
                if response.status != 200:
                    reason = json.loads(
                            response.read().decode('utf-8'))['reason']
                    raise RouterException(
                        "APNS Transmit Error {}:{}".format(response.status,
                                                           reason),
                        status_code=502,
                        response_body="APNS could not process "
                                      "your message {}".format(reason),
                    )
                break
            except (HTTP20Error, IOError):
                connection.close()
                attempt += 1
                if attempt < self._max_retry:
                    continue
                raise
            finally:
                # Returning a closed connection to the pool is ok.
                # hyper will reconnect on .request()
                if connection:
                    self._return_connection(connection)

    def _get_connection(self):
        self._in_use_connections += 1
        if self.log:
            self.log.debug("Got New APNS connection")
        if self._in_use_connections > self._max_connections:
            raise RouterException(
                "Too many APNS requests, increase pool from {}".format(
                    self._max_connections
                ),
                status_code=503,
                response_body="APNS busy, please retry")
        try:
            connection = self.connections.pop()
            if self.log:
                self.log.debug("Got existing APNS connection")
            return connection._conn
        except IndexError:
            return HTTP20Connection(
                self.server,
                self.port,
                ssl_context=self.ssl_context,
                force_proto='h2')

    def _return_connection(self, connection):
        self._in_use_connections -= 1
        if self.log:
            self.log.debug("Done with APNS connection")
        conn = APNSConnection(connection)
        self.connections.appendleft(conn)

    def _reap(self):
        if self.log:
            self.log.debug("Reaping APNS connections")
        geezers = []
        for connection in self.connections:
            if connection._last_used < (time.time() - self._max_conn_ttl):
                if self.log:
                    self.log.debug("Found old connection")
                geezers.append(connection)
        try:
            for geezer in geezers:
                connection._conn.close()
                self.connections.remove(geezer)
        except ValueError:
            pass
        time.sleep(self._reap_sleep)
