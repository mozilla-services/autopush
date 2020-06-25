import httplib
import json
import logging
import os
import random
import socket
import sys
import time
import urlparse
import uuid
from contextlib import contextmanager
from distutils.spawn import find_executable
from StringIO import StringIO
from httplib import HTTPResponse  # noqa

import pytest
import treq
from mock import Mock, call, patch
from unittest.case import SkipTest

from zope.interface import implementer

import ecdsa
import ssl
import twisted.internet.base
import websocket
from cryptography.fernet import Fernet
from jose import jws
from requests.exceptions import Timeout
from typing import Optional  # noqa
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.threads import deferToThread
from twisted.logger import globalLogPublisher
from twisted.test.proto_helpers import AccumulatingProtocol
from twisted.trial import unittest
from twisted.web.client import Agent, FileBodyProducer
from twisted.web.http_headers import Headers

import autopush.db as db
from autopush import __version__
from autopush.config import AutopushConfig
from autopush.db import (
    get_month,
    has_connected_this_month,
    Message,
)
from autopush.exceptions import ItemNotFound
from autopush.logging import begin_or_register
from autopush.main import ConnectionApplication, EndpointApplication
from autopush.utils import base64url_encode, normalize_id
from autopush.metrics import SinkMetrics, DatadogMetrics
import autopush.tests
from autopush.tests.support import _TestingLogObserver
from autopush.websocket import PushServerFactory

log = logging.getLogger(__name__)

twisted.internet.base.DelayedCall.debug = True


def setup_module():
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    if "SKIP_INTEGRATION" in os.environ:  # pragma: nocover
        raise SkipTest("Skipping integration tests")


def _get_vapid(key=None, payload=None):
    if not payload:
        payload = {"aud": "https://pusher_origin.example.com",
                   "exp": int(time.time()) + 86400,
                   "sub": "mailto:admin@example.com"}
    if not key:
        key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    vk = key.get_verifying_key()
    auth = jws.sign(payload, key, algorithm="ES256").strip('=')
    crypto_key = base64url_encode('\4' + vk.to_string())
    return {"auth": auth,
            "crypto-key": crypto_key,
            "key": key}


class Client(object):
    """Test Client"""
    def __init__(self, url, sslcontext=None):
        self.url = url
        self.uaid = None
        self.ws = None
        self.use_webpush = True
        self.channels = {}
        self.messages = {}
        self.notif_response = None  # type: Optional[HTTPResponse]
        self._crypto_key = """\
keyid="http://example.org/bob/keys/123;salt="XZwpw6o37R-6qoZjw6KwAw"\
"""
        self.sslcontext = sslcontext
        self.headers = {
            "User-Agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) "
            "Gecko/20100101 Firefox/61.0"
        }

    def __getattribute__(self, name):
        # Python fun to turn all functions into deferToThread functions
        f = object.__getattribute__(self, name)
        if name.startswith("__"):
            return f

        if callable(f):
            return lambda *args, **kwargs: deferToThread(f, *args, **kwargs)
        else:
            return f

    def connect(self, connection_port=None):
        url = self.url
        if connection_port:  # pragma: nocover
            url = "ws://localhost:{}/".format(connection_port)
        self.ws = websocket.create_connection(url, header=self.headers)
        return self.ws.connected

    def hello(self, uaid=None, services=None):
        if self.channels:
            chans = self.channels.keys()
        else:
            chans = []
        hello_dict = dict(messageType="hello",
                          use_webpush=True,
                          channelIDs=chans)
        if uaid or self.uaid:
            hello_dict["uaid"] = uaid or self.uaid
        if services:  # pragma: nocover
            hello_dict["broadcasts"] = services
        msg = json.dumps(hello_dict)
        log.debug("Send: %s", msg)
        self.ws.send(msg)
        result = json.loads(self.ws.recv())
        log.debug("Recv: %s", result)
        assert result["status"] == 200
        assert "-" not in result["uaid"]
        if self.uaid and self.uaid != result["uaid"]:  # pragma: nocover
            log.debug("Mismatch on re-using uaid. Old: %s, New: %s",
                      self.uaid, result["uaid"])
            self.channels = {}
        self.uaid = result["uaid"]
        return result

    def broadcast_subscribe(self, services):  # pragma: nocover
        msg = json.dumps(dict(messageType="broadcast_subscribe",
                              broadcasts=services))
        log.debug("Send: %s", msg)
        self.ws.send(msg)

    def register(self, chid=None, key=None, status=200):
        chid = chid or str(uuid.uuid4())
        msg = json.dumps(dict(messageType="register",
                              channelID=chid,
                              key=key))
        log.debug("Send: %s", msg)
        self.ws.send(msg)
        rcv = self.ws.recv()
        result = json.loads(rcv)
        log.debug("Recv: %s", result)
        assert result["status"] == status
        assert result["channelID"] == chid
        if status == 200:
            self.channels[chid] = result["pushEndpoint"]
        return result

    def unregister(self, chid):
        msg = json.dumps(dict(messageType="unregister", channelID=chid))
        log.debug("Send: %s", msg)
        self.ws.send(msg)
        result = json.loads(self.ws.recv())
        log.debug("Recv: %s", result)
        return result

    def delete_notification(self, channel, message=None, status=204):
        messages = self.messages[channel]
        if not message:
            message = random.choice(messages)

        log.debug("Delete: %s", message)
        url = urlparse.urlparse(message)
        http = None
        if url.scheme == "https":  # pragma: nocover
            http = httplib.HTTPSConnection(url.netloc, context=self.sslcontext)
        else:
            http = httplib.HTTPConnection(url.netloc)

        http.request("DELETE", url.path)
        resp = http.getresponse()
        http.close()
        assert resp.status == status

    def send_notification(self, channel=None, version=None, data=None,
                          use_header=True, status=None, ttl=200,
                          timeout=0.2, vapid=None, endpoint=None,
                          topic=None):
        if not channel:
            channel = random.choice(self.channels.keys())

        endpoint = endpoint or self.channels[channel]
        url = urlparse.urlparse(endpoint)
        http = None
        if url.scheme == "https":  # pragma: nocover
            http = httplib.HTTPSConnection(url.netloc, context=self.sslcontext)
        else:
            http = httplib.HTTPConnection(url.netloc)

        headers = {}
        if ttl is not None:
            headers = {"TTL": str(ttl)}
        if use_header:
            headers.update({
                "Content-Type": "application/octet-stream",
                "Content-Encoding": "aesgcm",
                "Encryption": self._crypto_key,
                "Crypto-Key": 'keyid="a1"; dh="JcqK-OLkJZlJ3sJJWstJCA"',
            })
        if vapid:
            headers.update({
                "Authorization": "Bearer " + vapid.get('auth')
            })
            ckey = 'p256ecdsa="' + vapid.get('crypto-key') + '"'
            headers.update({
                'Crypto-Key': headers.get('Crypto-Key') + ';' + ckey
            })
        if topic:
            headers["Topic"] = topic
        body = data or ""
        method = "POST"
        status = status or 201

        log.debug("%s body: %s", method, body)
        http.request(method, url.path.encode("utf-8"), body, headers)
        resp = http.getresponse()
        log.debug("%s Response (%s): %s", method, resp.status, resp.read())
        http.close()
        assert resp.status == status
        self.notif_response = resp
        location = resp.getheader("Location", None)
        log.debug("Response Headers: %s", resp.getheaders())
        if status >= 200 and status < 300:
            assert location is not None
        if status == 201 and ttl is not None:
            ttl_header = resp.getheader("TTL")
            assert ttl_header == str(ttl)
        if ttl != 0 and status == 201:
            assert location is not None
            if channel in self.messages:
                self.messages[channel].append(location)
            else:
                self.messages[channel] = [location]

        # Pull the notification if connected
        if self.ws and self.ws.connected:
            return object.__getattribute__(self, "get_notification")(timeout)
        else:
            return resp

    def get_notification(self, timeout=1):
        orig_timeout = self.ws.gettimeout()
        self.ws.settimeout(timeout)
        try:
            d = self.ws.recv()
            log.debug("Recv: %s", d)
            return json.loads(d)
        except Exception:
            return None
        finally:
            self.ws.settimeout(orig_timeout)

    def get_broadcast(self, timeout=1):  # pragma: nocover
        orig_timeout = self.ws.gettimeout()
        self.ws.settimeout(timeout)
        try:
            d = self.ws.recv()
            log.debug("Recv: %s", d)
            result = json.loads(d)
            assert result.get("messageType") == "broadcast"
            return result
        except Exception:  # pragma: nocover
            return None
        finally:
            self.ws.settimeout(orig_timeout)

    def ping(self):
        log.debug("Send: %s", "{}")
        self.ws.send("{}")
        result = self.ws.recv()
        log.debug("Recv: %s", result)
        assert result == "{}"
        return result

    def ack(self, channel, version):
        msg = json.dumps(dict(messageType="ack",
                              updates=[dict(channelID=channel,
                                            version=version)]))
        log.debug("Send: %s", msg)
        self.ws.send(msg)

    def disconnect(self):
        self.ws.close()

    def sleep(self, duration):  # pragma: nocover
        time.sleep(duration)

    def wait_for(self, func):
        """Waits several seconds for a function to return True"""
        times = 0
        while not func():  # pragma: nocover
            time.sleep(1)
            times += 1
            if times > 9:  # pragma: nocover
                break


ROUTER_TABLE = os.environ.get("ROUTER_TABLE", "router_int_test")
MESSAGE_TABLE = os.environ.get("MESSAGE_TABLE", "message_int_test")


class IntegrationBase(unittest.TestCase):
    track_objects = True
    track_objects_excludes = [AutopushConfig, PushServerFactory]

    connection_port = 9010
    endpoint_port = 9020
    router_port = 9030

    _endpoint_defaults = dict(
        hostname='localhost',
        port=endpoint_port,
        endpoint_port=endpoint_port,
        endpoint_scheme='http',
        router_port=router_port,
        statsd_host=None,
        router_table=dict(tablename=ROUTER_TABLE),
        message_table=dict(tablename=MESSAGE_TABLE),
        use_cryptography=True,
    )

    _conn_defaults = dict(
        hostname='localhost',
        port=connection_port,
        endpoint_port=endpoint_port,
        router_port=router_port,
        endpoint_scheme='http',
        statsd_host=None,
        router_table=dict(tablename=ROUTER_TABLE),
        message_table=dict(tablename=MESSAGE_TABLE),
        use_cryptography=True,
    )

    def setUp(self):
        self.logs = _TestingLogObserver()
        begin_or_register(self.logs)
        self.addCleanup(globalLogPublisher.removeObserver, self.logs)

        crypto_key = Fernet.generate_key()
        ep_conf = AutopushConfig(
            crypto_key=crypto_key,
            **self.endpoint_kwargs()
        )
        conn_conf = AutopushConfig(
            crypto_key=crypto_key,
            **self.conn_kwargs()
        )

        # Endpoint HTTP router
        self.ep = ep = EndpointApplication(
            conf=ep_conf,
            resource=autopush.tests.boto_resource
        )
        ep.setup(rotate_tables=False)
        ep.startService()
        self.addCleanup(ep.stopService)

        # Websocket server
        self.conn = conn = ConnectionApplication(
            conf=conn_conf,
            resource=autopush.tests.boto_resource
        )
        conn.setup(rotate_tables=False)
        conn.startService()
        self.addCleanup(conn.stopService)

    def endpoint_kwargs(self):
        return self._endpoint_defaults

    def conn_kwargs(self):
        return self._conn_defaults

    @inlineCallbacks
    def quick_register(self, sslcontext=None):
        client = Client("ws://localhost:{}/".format(self.connection_port),
                        sslcontext=sslcontext)
        yield client.connect()
        yield client.hello()
        yield client.register()
        returnValue(client)

    @inlineCallbacks
    def shut_down(self, client=None):
        if client:
            yield client.disconnect()

    @contextmanager
    def legacy_endpoint(self):
        self.ep.conf._notification_legacy = True
        yield
        self.ep.conf._notification_legacy = False


class SSLEndpointMixin(object):

    certs = os.path.join(os.path.dirname(__file__), "certs")
    servercert = os.path.join(certs, "server.pem")

    def endpoint_kwargs(self):
        return dict(
            super(SSLEndpointMixin, self).endpoint_kwargs(),
            ssl=dict(key=self.servercert, cert=self.servercert),
            endpoint_scheme='https'
        )

    def conn_kwargs(self):
        return dict(
            super(SSLEndpointMixin, self).conn_kwargs(),
            endpoint_scheme='https'
        )

    def client_SSLCF(self, certfile):
        """Return an IPolicyForHTTPS for verifiying tests' server cert.

        Optionally configures a client cert.

        """
        from twisted.internet.ssl import (
            Certificate, PrivateCertificate, optionsForClientTLS)
        from twisted.web.iweb import IPolicyForHTTPS

        with open(self.servercert) as fp:
            servercert = Certificate.loadPEM(fp.read())
        if certfile:
            with open(self.unauth_client) as fp:
                unauth_client = PrivateCertificate.loadPEM(fp.read())
        else:
            unauth_client = None

        @implementer(IPolicyForHTTPS)
        class UnauthClientPolicyForHTTPS(object):
            def creatorForNetloc(self, hostname, port):
                return optionsForClientTLS(
                    hostname.decode('ascii'),
                    trustRoot=servercert,
                    clientCertificate=unauth_client)
        return UnauthClientPolicyForHTTPS()

    def _create_context(self, certfile):
        """Return a client SSLContext

        Optionally configures a client cert.

        """
        import ssl
        context = ssl.create_default_context()
        if certfile:
            context.load_cert_chain(certfile)
        context.load_verify_locations(self.servercert)
        return context


class Test_Data(IntegrationBase):
    @inlineCallbacks
    def test_webpush_bad_url(self):
        client = yield self.quick_register()
        yield client.disconnect()
        endpoint = client.channels.values()[0]
        endpoint = endpoint.replace("wpush", "push")
        resp = yield client.send_notification(endpoint=endpoint, status=404)
        assert resp.getheader("Content-Type") == "application/json"

    @inlineCallbacks
    def test_webpush_data_delivery_to_connected_client(self):
        client = yield self.quick_register()
        assert client.channels
        chan = client.channels.keys()[0]

        # Invalid UTF-8 byte sequence.
        data = b"\xc3\x28\xa0\xa1\xe2\x28\xa1"

        result = yield client.send_notification(data=data)
        assert result is not None
        assert result["messageType"] == "notification"
        assert result["channelID"] == chan
        assert result["data"] == "wyigoeIooQ"
        assert self.logs.logged_ci(lambda ci: 'message_size' in ci)
        assert self.logs.logged_ci(
            lambda ci: normalize_id(ci['channel_id']) == chan)
        assert self.logs.logged_ci(
            lambda ci: ci['encoding'] == "aesgcm"
        )
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_data_delivery_to_connected_client_uaid_fail(self):
        client = yield self.quick_register()
        self.conn.db.router.get_uaid = Mock(side_effect=ItemNotFound)
        assert client.channels
        chan = client.channels.keys()[0]

        # Invalid UTF-8 byte sequence.
        data = b"\xc3\x28\xa0\xa1\xe2\x28\xa1"

        result = yield client.send_notification(data=data)
        assert result is not None
        assert result["messageType"] == "notification"
        assert result["channelID"] == chan
        assert result["data"] == "wyigoeIooQ"
        assert self.logs.logged_ci(lambda ci: 'message_size' in ci)
        assert self.logs.logged_ci(
            lambda ci: ci['encoding'] == "aesgcm"
        )
        yield self.shut_down(client)

    @inlineCallbacks
    def test_legacy_simplepush_record(self):
        """convert to webpush record and see if it works"""
        client = yield self.quick_register()
        uaid = "deadbeef00000000deadbeef00000001"
        self.ep.db.router.get_uaid = Mock(
            return_value={'router_type': 'simplepush',
                          'uaid': uaid,
                          'current_month': self.ep.db.current_msg_month})
        safe = db.Message.all_channels
        db.Message.all_channels = Mock(return_value=(True, client.channels))
        yield client.send_notification()
        db.Message.all_channels = safe
        yield self.shut_down(client)

    @patch("autopush.metrics.datadog")
    @inlineCallbacks
    def test_webpush_data_delivery_to_disconnected_client(self, m_ddog):
        tests = {
            "d248d4e0-0ef4-41d9-8db5-2533ad8e4041": dict(
                data=b"\xe2\x82\x28\xf0\x28\x8c\xbc", result="4oIo8CiMvA"),

            "df2363be-4d55-49c5-a1e3-aeae9450692e": dict(
                data=b"\xf0\x90\x28\xbc\xf0\x28\x8c\x28",
                result="8JAovPAojCg"),

            "6c33e055-5762-47e5-b90c-90ad9bfe3f53": dict(
                data=b"\xc3\x28\xa0\xa1\xe2\x28\xa1", result="wyigoeIooQ"),
        }
        # Piggy back a check for stored source metrics
        self.conn.db.metrics = DatadogMetrics(
            "someapikey", "someappkey", namespace="testpush",
            hostname="localhost")
        self.conn.db.metrics._client = Mock()

        client = Client("ws://localhost:{}/".format(self.connection_port))
        yield client.connect()
        yield client.hello()
        for chan, test in tests.items():
            yield client.register(chid=chan)

        yield client.disconnect()
        for chan, test in tests.items():
            yield client.send_notification(channel=chan, data=test["data"])

        yield client.connect()
        yield client.hello()

        for chan in tests:
            result = yield client.get_notification()
            assert result is not None
            chan = result["channelID"]
            test = tests[chan]
            assert result["data"] == test["result"]
            headers = result["headers"]
            assert "crypto_key" in headers
            assert "encryption" in headers
            assert "encoding" in headers
            yield client.ack(chan, result["version"])

        assert self.logs.logged_ci(lambda ci: 'message_size' in ci)
        inc_call = self.conn.db.metrics._client.increment.call_args_list[5]
        assert inc_call[1]['tags'] == ['source:Stored']
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_data_save_fail(self):
        chan = "d248d4e0-0ef4-41d9-8db5-2533ad8e4041"
        test = dict(data=b"\xe2\x82\x28\xf0\x28\x8c\xbc", result="4oIo8CiMvA")
        client = Client("ws://localhost:{}/".format(self.connection_port))
        yield client.connect()
        yield client.hello()
        yield client.register(chid=chan)
        yield client.disconnect()
        safe = db.Message.store_message
        db.Message.store_message = Mock(
            return_value=False)
        yield client.send_notification(channel=chan,
                                       data=test["data"],
                                       status=201)
        db.Message.store_message = safe
        yield self.shut_down(client)


class TestLoop(IntegrationBase):
    @inlineCallbacks
    def test_basic_deliver(self):
        client = yield self.quick_register()
        result = yield client.send_notification()
        assert result != {}
        yield self.shut_down(client)

    @inlineCallbacks
    def test_can_ping(self):
        client = yield self.quick_register()
        yield client.ping()
        yield self.shut_down(client)

    @inlineCallbacks
    def test_uaid_resumption_on_reconnect(self):
        client = yield self.quick_register()
        chan = client.channels.keys()[0]
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.send_notification()
        assert result != {}
        assert result["channelID"] == chan
        yield self.shut_down(client)


class TestWebPush(IntegrationBase):

    @property
    def _ws_url(self):
        return self.conn.conf.ws_url

    @inlineCallbacks
    def test_hello_only_has_three_calls(self):
        db.TRACK_DB_CALLS = True
        client = Client(self._ws_url)
        yield client.connect()
        result = yield client.hello()
        assert result != {}
        assert result["use_webpush"] is True
        yield client.wait_for(lambda: len(db.DB_CALLS) == 3)
        assert db.DB_CALLS == ['register_user', 'fetch_messages',
                               'fetch_timestamp_messages']
        db.DB_CALLS = []
        db.TRACK_DB_CALLS = False

        yield self.shut_down(client)

    @inlineCallbacks
    def test_hello_echo(self):
        client = Client(self._ws_url)
        yield client.connect()
        result = yield client.hello()
        assert result != {}
        assert result["use_webpush"] is True
        yield self.shut_down(client)

    @inlineCallbacks
    def test_hello_with_bad_prior_uaid(self):
        non_uaid = uuid.uuid4().hex
        client = Client(self._ws_url)
        yield client.connect()
        result = yield client.hello(uaid=non_uaid)
        assert result != {}
        assert result["uaid"] != non_uaid
        assert result["use_webpush"] is True
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        result = yield client.send_notification(data=data)
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        yield self.shut_down(client)
        log_event = self.logs.logged_session()
        assert log_event["connection_type"] == "webpush"
        assert log_event["direct_storage"] == 1
        assert log_event["ua_os_ver"] == "10.13"
        assert log_event["ua_browser_ver"] == "61.0"

    @inlineCallbacks
    def test_topic_basic_delivery(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        result = yield client.send_notification(data=data, topic="Inbox")
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        yield self.shut_down(client)

    @inlineCallbacks
    def test_topic_replacement_delivery(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        yield client.send_notification(data=data, topic="Inbox")
        yield client.send_notification(data=data2, topic="Inbox")
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data2)
        assert result["messageType"] == "notification"
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_topic_no_delivery_on_reconnect(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        yield client.send_notification(data=data, topic="Inbox")
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification(timeout=10)
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        yield client.ack(result["channelID"], result["version"])
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_vapid(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        vapid_info = _get_vapid()
        result = yield client.send_notification(data=data, vapid=vapid_info)
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        assert self.logs.logged_ci(lambda ci: 'router_key' in ci)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_invalid_vapid(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        vapid_info = _get_vapid()
        vapid_info['crypto-key'] = "invalid"
        yield client.send_notification(
            data=data,
            vapid=vapid_info,
            status=401)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_invalid_vapid_exp(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        vapid_info = _get_vapid(
            payload={"aud": "https://pusher_origin.example.com",
                     "exp": '@',
                     "sub": "mailto:admin@example.com"})
        yield client.send_notification(
            data=data,
            vapid=vapid_info,
            status=401)

        vapid_info = _get_vapid(
            payload={"aud": "https://pusher_origin.example.com",
                     "exp": ['@'],
                     "sub": "mailto:admin@example.com"})
        yield client.send_notification(
            data=data,
            vapid=vapid_info,
            status=401)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_invalid_vapid_auth(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        vapid_info = _get_vapid()
        vapid_info['auth'] = ""
        yield client.send_notification(
            data=data,
            vapid=vapid_info,
            status=401)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_invalid_signature(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        vapid_info = _get_vapid(
            payload={"aud": "https://pusher_origin.example.com",
                     "sub": "mailto:admin@example.com"})
        vapid_info['auth'] = vapid_info['auth'][:-3] + "bad"
        yield client.send_notification(
            data=data,
            vapid=vapid_info,
            status=401)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_invalid_vapid_ckey(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        vapid_info = _get_vapid()
        vapid_info['crypto-key'] = "invalid|"
        yield client.send_notification(
            data=data,
            vapid=vapid_info,
            status=401)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_delivery_repeat_without_ack(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        assert client.channels
        yield client.send_notification(data=data)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] == base64url_encode(data)

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] == base64url_encode(data)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_delivery_repeat_without_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        assert client.channels
        yield client.send_notification(data=data)
        yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_legacy_delivery_with_single_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        assert client.channels
        with self.legacy_endpoint():
            yield client.send_notification(data=data)
            yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification(timeout=5)
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])
        assert result["messageType"] == "notification"
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_delivery_with_single_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        assert client.channels
        yield client.send_notification(data=data)
        yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] == base64url_encode(data)
        result2 = yield client.get_notification()
        assert result2 != {}
        assert result2["data"] == base64url_encode(data2)
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        result2 = yield client.get_notification()
        assert result2 != {}
        assert result2["data"] == base64url_encode(data2)
        yield client.ack(result2["channelID"], result2["version"])

        # Verify no messages are delivered
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_delivery_with_multiple_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        assert client.channels
        yield client.send_notification(data=data)
        yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result != {}
        assert result["data"] in map(base64url_encode, [data, data2])
        result2 = yield client.get_notification()
        assert result2 != {}
        assert result2["data"] in map(base64url_encode, [data, data2])
        yield client.ack(result2["channelID"], result2["version"])
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_no_delivery_to_unregistered(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()  # type: Client
        assert client.channels
        chan = client.channels.keys()[0]

        result = yield client.send_notification(data=data)
        assert result["channelID"] == chan
        assert result["data"] == base64url_encode(data)
        yield client.ack(result["channelID"], result["version"])

        yield client.unregister(chan)
        result = yield client.send_notification(data=data, status=410)

        # Verify cache-control
        assert client.notif_response.getheader("Cache-Control") == \
            "max-age=86400"

        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_not_present_not_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        yield client.send_notification(data=data, ttl=None, status=400)
        self.flushLoggedErrors()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_not_present_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        result = yield client.send_notification(data=data, ttl=None)
        assert result is not None
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_not_present_connected_no_ack(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        result = yield client.send_notification(data=data, ttl=None)
        assert result is not None
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_0_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        result = yield client.send_notification(data=data, ttl=0)
        assert result is not None
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data)
        assert result["messageType"] == "notification"
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_0_not_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        yield client.send_notification(data=data, ttl=0)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_expired(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        yield client.send_notification(data=data, ttl=1)
        time.sleep(1.5)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_neg(self):
        client = yield self.quick_register()
        yield client.send_notification(ttl=-1, status=400)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_batch_expired_and_good_one(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        for x in range(0, 12):
            yield client.send_notification(data=data, ttl=1)

        yield client.send_notification(data=data2, ttl=200)
        time.sleep(1.5)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification(timeout=4)
        assert result is not None
        assert result["headers"]["encryption"] == client._crypto_key
        assert result["data"] == base64url_encode(data2)
        assert result["messageType"] == "notification"
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_batch_partly_expired_and_good_one(self):
        data = str(uuid.uuid4())
        data1 = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register()
        yield client.disconnect()
        for x in range(0, 6):
            yield client.send_notification(data=data)

        for x in range(0, 6):
            yield client.send_notification(data=data1, ttl=1)

        yield client.send_notification(data=data2)
        time.sleep(1.5)
        yield client.connect()
        yield client.hello()

        # Pull out and ack the first
        for x in range(0, 6):
            result = yield client.get_notification(timeout=4)
            assert result is not None
            assert result["data"] == base64url_encode(data)
            yield client.ack(result["channelID"], result["version"])

        # Should have one more that is data2, this will only arrive if the
        # other six were acked as that hits the batch size
        result = yield client.get_notification(timeout=4)
        assert result is not None
        assert result["data"] == base64url_encode(data2)

        # No more
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_message_without_crypto_headers(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register()
        result = yield client.send_notification(data=data, use_header=False,
                                                status=400)
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_message_with_topic(self):
        data = str(uuid.uuid4())
        self.conn.db.metrics = Mock(spec=SinkMetrics)
        client = yield self.quick_register()
        yield client.send_notification(data=data, topic="topicname")
        self.conn.db.metrics.increment.assert_has_calls([
            call('ua.command.hello'),
            call('ua.command.register'),
            call('ua.notification.topic')
        ])
        yield self.shut_down(client)

    @inlineCallbacks
    def test_empty_message_without_crypto_headers(self):
        client = yield self.quick_register()
        result = yield client.send_notification(use_header=False)
        assert result is not None
        assert result["messageType"] == "notification"
        assert "headers" not in result
        assert "data" not in result
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.send_notification(use_header=False)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is not None
        assert "headers" not in result
        assert "data" not in result
        yield client.ack(result["channelID"], result["version"])

        yield self.shut_down(client)

    @inlineCallbacks
    def test_empty_message_with_crypto_headers(self):
        client = yield self.quick_register()
        result = yield client.send_notification()
        assert result is not None
        assert result["messageType"] == "notification"
        assert "headers" not in result
        assert "data" not in result

        result2 = yield client.send_notification()
        # We shouldn't store headers for blank messages.
        assert result2 is not None
        assert result2["messageType"] == "notification"
        assert "headers" not in result2
        assert "data" not in result2

        yield client.ack(result["channelID"], result["version"])
        yield client.ack(result2["channelID"], result2["version"])

        yield client.disconnect()
        yield client.send_notification()
        yield client.connect()
        yield client.hello()
        result3 = yield client.get_notification()
        assert result3 is not None
        assert "headers" not in result3
        assert "data" not in result3
        yield client.ack(result3["channelID"], result3["version"])

        yield self.shut_down(client)

    @inlineCallbacks
    def test_delete_saved_notification(self):
        client = yield self.quick_register()
        yield client.disconnect()
        assert client.channels
        chan = client.channels.keys()[0]
        yield client.send_notification()
        yield client.delete_notification(chan)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        assert result is None
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_monthly_rotation(self):
        from autopush.db import make_rotating_tablename
        client = yield self.quick_register()
        yield client.disconnect()

        # Move the client back one month to the past
        last_month = make_rotating_tablename(
            prefix=self.conn.conf.message_table.tablename, delta=-1)
        lm_message = Message(last_month, boto_resource=self.conn.db.resource)
        yield deferToThread(
            self.conn.db.router.update_message_month,
            client.uaid,
            last_month,
        )

        # Verify the move
        c = yield deferToThread(self.conn.db.router.get_uaid,
                                client.uaid)
        assert c["current_month"] == last_month

        # Verify last_connect is current, then move that back
        assert has_connected_this_month(c)
        today = get_month(delta=-1)
        last_connect = int("%s%s020001" % (today.year,
                                           str(today.month).zfill(2)))

        yield deferToThread(
            self.conn.db.router._update_last_connect,
            client.uaid,
            last_connect)
        c = yield deferToThread(self.conn.db.router.get_uaid,
                                client.uaid)
        assert has_connected_this_month(c) is False

        # Move the clients channels back one month
        exists, chans = yield deferToThread(
            self.conn.db.message.all_channels,
            client.uaid
        )
        assert exists is True
        assert len(chans) == 1
        yield deferToThread(
            lm_message.save_channels,
            client.uaid,
            chans,
        )

        # Remove the channels entry entirely from this month
        yield deferToThread(
            self.conn.db.message.table.delete_item,
            Key={'uaid': client.uaid, 'chidmessageid': ' '}
        )

        # Verify the channel is gone
        exists, chans = yield deferToThread(
            self.conn.db.message.all_channels,
            client.uaid,
        )
        assert exists is False
        assert len(chans) == 0

        # Send in a notification, verify it landed in last months notification
        # table
        data = uuid.uuid4().hex
        yield client.send_notification(data=data)
        ts, notifs = yield deferToThread(lm_message.fetch_timestamp_messages,
                                         uuid.UUID(client.uaid),
                                         " ")
        assert len(notifs) == 1

        # Connect the client, verify the migration
        yield client.connect()
        yield client.hello()

        # Pull down the notification
        result = yield client.get_notification()
        chan = client.channels.keys()[0]
        assert result is not None
        assert chan == result["channelID"]

        # Check that the client is going to rotate the month
        server_client = self.conn.clients[client.uaid]
        assert server_client.ps.rotate_message_table is True

        # Acknowledge the notification, which triggers the migration
        yield client.ack(chan, result["version"])

        # Wait up to 4 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 4:
            c = yield deferToThread(
                self.conn.db.router.get_uaid,
                client.uaid)
            if c["current_month"] == self.conn.db.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(
            self.conn.db.router.get_uaid,
            client.uaid)
        assert c["current_month"] == self.conn.db.current_msg_month
        assert server_client.ps.rotate_message_table is False

        # Verify the client moved last_connect
        assert has_connected_this_month(c) is True

        # Verify the channels were moved
        exists, chans = yield deferToThread(
            self.conn.db.message.all_channels,
            client.uaid
        )
        assert exists is True
        assert len(chans) == 1
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_monthly_rotation_prior_record_exists(self):
        from autopush.db import make_rotating_tablename
        client = yield self.quick_register()
        yield client.disconnect()

        # Move the client back one month to the past
        last_month = make_rotating_tablename(
            prefix=self.conn.conf.message_table.tablename, delta=-1)
        lm_message = Message(last_month,
                             boto_resource=autopush.tests.boto_resource)
        yield deferToThread(
            self.conn.db.router.update_message_month,
            client.uaid,
            last_month,
        )

        # Verify the move
        c = yield deferToThread(self.conn.db.router.get_uaid,
                                client.uaid)
        assert c["current_month"] == last_month

        # Verify last_connect is current, then move that back
        assert has_connected_this_month(c)
        today = get_month(delta=-1)
        yield deferToThread(
            self.conn.db.router._update_last_connect,
            client.uaid,
            int("%s%s020001" % (today.year, str(today.month).zfill(2))),
        )
        c = yield deferToThread(self.conn.db.router.get_uaid, client.uaid)
        assert has_connected_this_month(c) is False

        # Move the clients channels back one month
        exists, chans = yield deferToThread(
            self.conn.db.message.all_channels,
            client.uaid,
        )
        assert exists is True
        assert len(chans) == 1
        yield deferToThread(
            lm_message.save_channels,
            client.uaid,
            chans,
        )

        # Send in a notification, verify it landed in last months notification
        # table
        data = uuid.uuid4().hex
        yield client.send_notification(data=data)
        _, notifs = yield deferToThread(lm_message.fetch_timestamp_messages,
                                        uuid.UUID(client.uaid),
                                        " ")
        assert len(notifs) == 1

        # Connect the client, verify the migration
        yield client.connect()
        yield client.hello()

        # Pull down the notification
        result = yield client.get_notification()
        chan = client.channels.keys()[0]
        assert result is not None
        assert chan == result["channelID"]

        # Check that the client is going to rotate the month
        server_client = self.conn.clients[client.uaid]
        assert server_client.ps.rotate_message_table is True

        # Acknowledge the notification, which triggers the migration
        yield client.ack(chan, result["version"])

        # Wait up to 4 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 4:
            c = yield deferToThread(
                self.conn.db.router.get_uaid,
                client.uaid)
            if c["current_month"] == self.conn.db.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(self.conn.db.router.get_uaid, client.uaid)
        assert c["current_month"] == self.conn.db.current_msg_month
        assert server_client.ps.rotate_message_table is False

        # Verify the client moved last_connect
        assert has_connected_this_month(c) is True

        # Verify the channels were moved
        exists, chans = yield deferToThread(
            self.conn.db.message.all_channels,
            client.uaid
        )
        assert exists is True
        assert len(chans) == 1
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_monthly_rotation_no_channels(self):
        from autopush.db import make_rotating_tablename
        client = Client("ws://localhost:{}/".format(self.connection_port))
        yield client.connect()
        yield client.hello()
        yield client.disconnect()

        # Move the client back one month to the past
        last_month = make_rotating_tablename(
            prefix=self.conn.conf.message_table.tablename, delta=-1)
        yield deferToThread(
            self.conn.db.router.update_message_month,
            client.uaid,
            last_month
        )

        # Verify the move
        c = yield deferToThread(self.conn.db.router.get_uaid,
                                client.uaid
                                )
        assert c["current_month"] == last_month

        # Verify there's no channels
        exists, chans = yield deferToThread(
            self.conn.db.message.all_channels,
            client.uaid,
        )
        assert exists is False
        assert len(chans) == 0

        # Connect the client, verify the migration
        yield client.connect()
        yield client.hello()

        # Check that the client is going to rotate the month
        server_client = self.conn.clients[client.uaid]
        assert server_client.ps.rotate_message_table is True

        # Wait up to 2 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 2:
            c = yield deferToThread(
                self.conn.db.router.get_uaid,
                client.uaid,
            )
            if c["current_month"] == self.conn.db.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(self.conn.db.router.get_uaid,
                                client.uaid)
        assert c["current_month"] == self.conn.db.current_msg_month
        assert server_client.ps.rotate_message_table is False
        yield self.shut_down(client)

    @inlineCallbacks
    def test_with_key(self):
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        claims = {"aud": "http://example.com",
                  "exp": int(time.time()) + 86400,
                  "sub": "a@example.com"}
        vapid = _get_vapid(private_key, claims)
        pk_hex = vapid['crypto-key']
        chid = str(uuid.uuid4())
        client = Client("ws://localhost:9010/")
        yield client.connect()
        yield client.hello()
        yield client.register(chid=chid, key=pk_hex)

        # Send an update with a properly formatted key.
        yield client.send_notification(vapid=vapid)

        # now try an invalid key.
        new_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        vapid = _get_vapid(new_key, claims)

        yield client.send_notification(
            vapid=vapid,
            status=401)

        yield self.shut_down(client)


class TestClientCerts(SSLEndpointMixin, IntegrationBase):

    def setUp(self):
        certs = self.certs
        self.auth_client = os.path.join(certs, "client1.pem")
        self.unauth_client = os.path.join(certs, "client2.pem")
        with open(os.path.join(certs, "client1_sha256.txt")) as fp:
            client1_sha256 = fp.read().strip()
        self._client_certs = {client1_sha256: 'partner1'}
        IntegrationBase.setUp(self)

    def endpoint_kwargs(self):
        return dict(
            super(TestClientCerts, self).endpoint_kwargs(),
            client_certs=self._client_certs
        )

    @inlineCallbacks
    def test_client_cert_webpush(self):
        try:
            client = yield self.quick_register(
                sslcontext=self._create_context(self.auth_client))
        except ssl.SSLError as ex:
            if ex.reason == "CA_MD_TOO_WEAK":
                raise SkipTest("Old test cert used")
            raise
        yield client.disconnect()
        assert client.channels
        chan = client.channels.keys()[0]

        yield client.send_notification()
        yield client.delete_notification(chan)
        result = yield client.get_notification()
        assert result is None

        yield self.shut_down(client)

    @inlineCallbacks
    def test_client_cert_unauth(self):
        yield self._test_unauth(self.unauth_client)

    @inlineCallbacks
    def test_no_client_cert(self):
        yield self._test_unauth(None)

    @inlineCallbacks
    def _test_unauth(self, certfile):
        try:
            client = yield self.quick_register(
                sslcontext=self._create_context(certfile))
        except ssl.SSLError as ex:
            if ex.reason == 'CA_MD_TOO_WEAK':
                raise SkipTest("Old test cert in use")
            raise
        yield client.disconnect()
        yield client.send_notification(status=401)
        assert self.logs.logged(
            lambda e: (e['log_format'] == "Failed TLS auth" and
                       (not certfile or
                        e['client_info']['tls_failed_cn'] == 'localhost')
                       ))

        response, body = yield _agent(
            'DELETE',
            "https://localhost:9020/m/foo",
            contextFactory=self.client_SSLCF(certfile))
        assert response.code == 401
        wwwauth = response.headers.getRawHeaders('www-authenticate')
        assert wwwauth == ['Transport mode="tls-client-certificate"']

    @inlineCallbacks
    def test_log_check_skips_auth(self):
        yield self._test_log_check_skips_auth(self.unauth_client)

    @inlineCallbacks
    def test_log_check_skips_auth_no_client_cert(self):
        yield self._test_log_check_skips_auth(None)

    @inlineCallbacks
    def _test_log_check_skips_auth(self, certfile):
        response, body = yield _agent(
            'GET',
            "https://localhost:9020/v1/err",
            contextFactory=self.client_SSLCF(certfile))
        assert response.code == 418
        payload = json.loads(body)
        assert payload['error'] == "Test Error"

    @inlineCallbacks
    def test_status_skips_auth(self):
        yield self._test_status_skips_auth(self.unauth_client)

    @inlineCallbacks
    def test_status_skips_auth_no_client_cert(self):
        yield self._test_status_skips_auth(None)

    @inlineCallbacks
    def _test_status_skips_auth(self, certfile):
        response, body = yield _agent(
            'GET',
            "https://localhost:9020/status",
            contextFactory=self.client_SSLCF(certfile))
        assert response.code == 200
        payload = json.loads(body)
        assert payload == dict(status="OK", version=__version__)

    @inlineCallbacks
    def test_health_skips_auth(self):
        yield self._test_health_skips_auth(self.unauth_client)

    @inlineCallbacks
    def test_health_skips_auth_no_client_cert(self):
        yield self._test_health_skips_auth(None)

    @inlineCallbacks
    def _test_health_skips_auth(self, certfile):
        response, body = yield _agent(
            'GET',
            "https://localhost:9020/health",
            contextFactory=self.client_SSLCF(certfile))
        assert response.code == 200
        payload = json.loads(body)
        assert payload['version'] == __version__


class TestHealth(IntegrationBase):
    @inlineCallbacks
    def test_status(self):
        response, body = yield _agent(
            'GET', "http://localhost:{}/status".format(self.connection_port))
        assert response.code == 200
        payload = json.loads(body)
        assert payload == dict(status="OK", version=__version__)


class TestGCMBridgeIntegration(IntegrationBase):

    senderID = "1009375523940"

    class MockReply(object):
        success = dict()
        canonicals = dict()
        failed_items = dict()
        not_registered = dict()
        failed = dict()
        retry_after = False
        retry_message = None

    def _add_router(self):
        from autopush.router.gcm import GCMRouter
        gcm = GCMRouter(
            self.ep.conf,
            {
                "ttl": 0,
                "dryrun": True,
                "max_data": 4096,
                "collapsekey": "test",
                "endpoint": "gcm-http.googleapis.com/gcm/send",
                "senderIDs": {self.senderID:
                              {"auth": "AIzaSyCx9PRtH8ByaJR3Cf"
                                       "Jamz0D2N0uaCgRGiI"}}
            },
            self.ep.db.metrics
        )
        self.ep.routers["gcm"] = gcm
        # Set up the mock call to avoid calling the live system.
        # The problem with calling the live system (even sandboxed) is that
        # you need a valid credential set from a mobile device, which can be
        # subject to change.
        self._mock_send = Mock(spec=treq.request)
        self._m_request = Deferred()
        self._mock_send.return_value = self._m_request
        self._m_response = Mock(spec=treq.response._Response)
        self._m_response.code = 200
        self._m_response.headers = Headers()
        self._m_resp_text = Deferred()
        self._m_response.text.return_value = self._m_resp_text
        gcm.gcmclients[self.senderID]._sender = self._mock_send

    def _set_content(self, content=None):
        if content is None:
            content = {
                "multicast_id": 5174939174563864884,
                "success": 1,
                "failure": 0,
                "canonical_ids": 0,
                "results": [
                    {
                        "message_id": "0:1510011451922224%7a0e7efbaab8b7cc"
                    }
                ]
            }
        self._m_resp_text.callback(json.dumps(content))
        self._m_request.callback(self._m_response)

    @inlineCallbacks
    def test_registration(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "gcm",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"chid": str(uuid.uuid4()),
             "token": uuid.uuid4().hex,
             }
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aesgcm"
        self._set_content()

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )

        ca_data = json.loads(self._mock_send.call_args[1]['data'])['data']
        assert response.code == 201
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        assert ca_data['chid'] == jbody['channelID']
        assert ca_data['con'] == content_encoding
        assert ca_data['cryptokey'] == crypto_key
        assert ca_data['enc'] == salt
        assert ca_data['body'] == base64url_encode(data)

    @inlineCallbacks
    def test_invalid_registration(self):
        self._add_router()

        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "invalid",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"chid": str(uuid.uuid4()),
             "token": uuid.uuid4().hex,
             }
        ))
        assert response.code == 400

    @inlineCallbacks
    def test_registration_aes128gcm(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "gcm",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"chid": str(uuid.uuid4()),
             "token": uuid.uuid4().hex,
             }
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        content_encoding = "aes128gcm"
        self._set_content()

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )

        ca_data = json.loads(self._mock_send.call_args[1]['data'])['data']
        assert response.code == 201
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        assert ca_data['chid'] == jbody['channelID']
        assert ca_data['con'] == content_encoding
        assert ca_data['body'] == base64url_encode(data)
        assert 'enc' not in ca_data

    @inlineCallbacks
    def test_registration_aes128gcm_bad_(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "gcm",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"chid": str(uuid.uuid4()),
             "token": uuid.uuid4().hex,
             }
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aes128gcm"
        self._set_content()

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "ttl": ["0"],
                "content-encoding": [content_encoding],
                "crypto-key": [crypto_key]
            }),
            body=data
        )

        assert response.code == 400
        assert "do not include 'dh' in " in body.lower()
        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "ttl": ["0"],
                "content-encoding": [content_encoding],
                "encryption": [salt]
            }),
            body=data
        )
        assert response.code == 400
        assert "do not include 'salt' in " in body.lower()

    @inlineCallbacks
    def test_registration_no_token(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "gcm",
            self.senderID,
        )
        self._set_content()

        response, body = yield _agent('POST', url, body=json.dumps(
            {
                "chid": str(uuid.uuid4()),
                "token": '',
            }
        ))
        assert response.code == 400


class TestFCMBridgeIntegration(IntegrationBase):

    senderID = "1009375523940"

    def _add_router(self):
        from autopush.router.fcm import FCMRouter
        fcm = FCMRouter(
            self.ep.conf,
            {
                "ttl": 0,
                "dryrun": True,
                "max_data": 4096,
                "collapsekey": "test",
                "creds": {
                    self.senderID: {
                        "auth": "AIzaSyCx9PRtH8ByaJR3CfJamz0D2N0uaCgRGiI"}
                },
            },
            self.ep.db.metrics
        )
        # Set up the mock call to avoid calling the live system.
        # The problem with calling the live system (even sandboxed) is that
        # you need a valid credential set from a mobile device, which can be
        # subject to change.
        reply = dict(
            canonical_ids=0,
            failure=0,
            results=[{}],
        )
        self._mock_send = Mock()
        fcm.clients[self.senderID].send_request = self._mock_send
        fcm.clients[self.senderID].parse_responses = Mock(return_value=reply)
        self.ep.routers["fcm"] = fcm

    @inlineCallbacks
    def test_registration(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "fcm",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"chid": str(uuid.uuid4()),
             "token": uuid.uuid4().hex,
             }
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aesgcm"

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )

        ca = json.loads(self._mock_send.call_args[0][0][0])
        ca_data = ca['data']
        assert response.code == 201
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        assert ca_data['chid'] == jbody['channelID']
        assert ca_data['con'] == content_encoding
        assert ca_data['cryptokey'] == crypto_key
        assert ca_data['enc'] == salt
        assert ca_data['body'] == base64url_encode(data)

    @inlineCallbacks
    def test_registration_update(self):
        """Ensure that a client bridge token update does not alter other
        required elements of the registration data.

        """
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "fcm",
            self.senderID,
        )
        old = uuid.uuid4().hex
        new = uuid.uuid4().hex
        response, body = yield _agent('POST', url, body=json.dumps(
            {
                "chid": str(uuid.uuid4()),
                "token": old
            }
        ))
        assert response.code == 200
        jbody = json.loads(body)
        rec_old = self.ep.db.router.get_uaid(jbody['uaid'])
        response, body = yield _agent(
            'PUT',
            "{}/{}".format(url, jbody['uaid']),
            headers=Headers(
                {"authorization": ["Bearer {}".format(jbody['secret'])]}
            ),
            body=json.dumps(
                {"token": new}
            )
        )
        assert response.code == 200
        rec_new = self.ep.db.router.get_uaid(jbody['uaid'])
        assert rec_new['router_data']['token'] == new
        assert rec_new['router_data']['app_id'] == \
            rec_old['router_data']['app_id']


class TestADMBrideIntegration(IntegrationBase):

    class MockReply(object):
        status_code = 200
        json = Mock(return_value=dict())

    token = ("amzn1.adm-registration.v3.VeryVeryLongString0fA1phaNumericStuff"
             + ("a" * 256))

    def _add_router(self):
        from autopush.router.adm import ADMRouter
        adm = ADMRouter(
            self.ep.conf,
            {
                "dev": {
                    "app_id": "amzn1.application.StringOfStuff",
                    "client_id": "amzn1.application-oa2-client.ev4nM0reStuff",
                    "client_secret": "deadbeef0000decafbad1111",
                }
            },
            self.ep.db.metrics,
        )

        self.ep.routers["adm"] = adm
        self._mock_send = Mock()
        self._mock_send.post = Mock()
        self._mock_reply = self.MockReply
        self._mock_send.post.return_value = self._mock_reply
        for profile in adm.profiles:
            adm.profiles[profile]._request = self._mock_send

    def test_bad_config(self):
        from autopush.router.adm import ADMRouter
        with pytest.raises(IOError):
            ADMRouter(
                self.ep.conf,
                {
                    "dev": {
                        "app_id": "amzn1.application.StringOfStuff",
                        "client_id":
                            "amzn1.application-oa2-client.ev4nM0reStuff",
                        "collapseKey": "simplepush",
                    }
                },
                self.ep.db.metrics,
            )

    @inlineCallbacks
    def test_missing_token_registration(self):
        self._add_router()
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "adm",
            "dev",
        )
        self._mock_reply.status_code = 200
        self._mock_reply.json.return_value = {
            "access_token": "token",
            "expires_in": 3000
        }
        response, body = yield _agent("POST", url, body=json.dumps(
            {"foo": self.token}
        ))
        assert response.code == 401
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "adm",
            "foo",
        )
        response, body = yield _agent("POST", url, body=json.dumps(
            {"token": self.token}
        ))
        assert response.code == 410

    @inlineCallbacks
    def test_successful(self):
        self._add_router()
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "adm",
            "dev",
        )
        self._mock_reply.status_code = 200
        self._mock_reply.json.return_value = {
            "access_token": "token",
            "expires_in": 3000
        }
        response, body = yield _agent("POST", url, body=json.dumps(
            {
                "chid": str(uuid.uuid4()),
                "token": self.token
            }
        ))
        assert response.code == 200
        jbody = json.loads(body)

        print("Response = {}", body)

        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aesgcm"

        self._mock_reply.json.return_value = dict(access_token="access.123")

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
                "topic": ["simplepush"]
            }),
            body=data
        )
        print ("Response: %s" % response.code)
        assert response.code == 201

        ca_data = self._mock_send.post.mock_calls[1][2]['json']['data']
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        assert ca_data['chid'] == jbody['channelID']
        assert ca_data['con'] == content_encoding
        assert ca_data['cryptokey'] == crypto_key
        assert ca_data['enc'] == salt
        assert ca_data['body'] == base64url_encode(data)

    @inlineCallbacks
    def test_bad_registration(self):
        self._add_router()
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "adm",
            "dev",
        )
        self._mock_reply.status_code = 400
        response, body = yield _agent("POST", url, body=json.dumps(
            {"token": self.token[:-100]}
        ))
        assert response.code == 400

    @inlineCallbacks
    def test_registration_update(self):
        """Ensure that a client bridge token update does not alter other
        required elements of the registration data.

        """
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "adm",
            "dev",
        )
        old = self.token
        new = self.token.replace('aa', 'bb')
        response, body = yield _agent('POST', url, body=json.dumps(
            {
                "chid": str(uuid.uuid4()),
                "token": old
            }
        ))
        assert response.code == 200
        jbody = json.loads(body)
        rec_old = self.ep.db.router.get_uaid(jbody['uaid'])

        response, body = yield _agent(
            'PUT',
            "{}/{}".format(url, jbody['uaid']),
            headers=Headers(
                {"authorization": ["Bearer {}".format(jbody['secret'])]}
            ),
            body=json.dumps(
                {"token": new}
            )
        )
        assert response.code == 200
        rec_new = self.ep.db.router.get_uaid(jbody['uaid'])
        assert rec_new['router_data']['token'] == new
        assert rec_new['router_data']['creds'] == \
            rec_old['router_data']['creds']

    @inlineCallbacks
    def test_bad_token_refresh(self):
        self._add_router()
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "adm",
            "dev",
        )
        self._mock_reply.status_code = 200
        response, body = yield _agent("POST", url, body=json.dumps(
            {"token": self.token}
        ))
        assert response.code == 200
        jbody = json.loads(body)
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aesgcm"
        self._mock_reply.status_code = 400
        self._mock_reply.text = "Test error"
        self._mock_reply.content = "Test content"
        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )
        assert response.code == 502
        self.flushLoggedErrors()

    @inlineCallbacks
    def test_bad_sends(self):
        from requests.exceptions import ConnectionError
        self._add_router()
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "adm",
            "dev",
        )
        self._mock_reply.status_code = 200
        response, body = yield _agent("POST", url, body=json.dumps(
            {"token": self.token}
        ))
        assert response.code == 200
        jbody = json.loads(body)
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aesgcm"

        # Test ADMAuth Error
        self._mock_reply.status_code = 400
        self._mock_reply.text = "Test error"
        self._mock_reply.content = "Test content"
        response, body = yield _agent(
            "POST",
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body="BunchOfStuff"
        )
        assert response.code == 502
        rbody = json.loads(body)
        assert rbody["errno"] == 901
        self.flushLoggedErrors()

        # fake a valid ADM key
        self.ep.routers["adm"].profiles["dev"]._auth_token = "SomeToken"
        self.ep.routers["adm"].profiles["dev"]._token_exp = time.time() + 300

        # Test ADM reply Error
        self._mock_reply.status_code = 400
        self._mock_reply.text = "Test error"
        self._mock_reply.content = "Test content"
        response, body = yield _agent(
            "POST",
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body="BunchOfStuff"
        )
        assert response.code == 500
        rbody = json.loads(body)

        # test Connection Error
        def fcon(*args, **kwargs):
            raise ConnectionError
        self._mock_send.post.side_effect = fcon
        response, body = yield _agent(
            "POST",
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body="BunchOfStuff"
        )
        assert response.code == 502
        rbody = json.loads(body)
        assert rbody["errno"] == 902
        self.flushLoggedErrors()

        # test timeout Error
        def fcon(*args, **kwargs):
            raise Timeout
        self._mock_send.post.side_effect = fcon
        response, body = yield _agent(
            "POST",
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body="BunchOfStuff"
        )
        assert response.code == 502
        rbody = json.loads(body)
        assert rbody["errno"] == 902
        self.flushLoggedErrors()

        # test random Exception
        def fcon(*args, **kwargs):
            raise Exception
        self._mock_send.post.side_effect = fcon
        response, body = yield _agent(
            "POST",
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body="BunchOfStuff"
        )
        assert response.code == 500

        self.flushLoggedErrors()


class TestAPNSBridgeIntegration(IntegrationBase):

    class m_response:
        status = 200

    def _add_router(self):
        from autopush.router.apnsrouter import APNSRouter
        apns = APNSRouter(
            self.ep.conf,
            {
                "firefox": {
                    "cert": "/home/user/certs/SimplePushDemo.p12_cert.pem",
                    "key": "/home/user/certs/SimplePushDemo.p12_key.pem",
                    "sandbox": True,
                }
            },
            self.ep.db.metrics,
            load_connections=False
        )
        self.ep.routers["apns"] = apns
        # Set up the mock call to avoid calling the live system.
        # The problem with calling the live system (even sandboxed) is that
        # you need a valid credential set from a mobile device, which can be
        # subject to change.
        self._mock_connection = Mock()
        self._mock_connection.request = Mock()
        self._mock_connection.get_response = Mock()
        self._mock_connection.get_response.return_value = self.m_response
        apns.apns["firefox"]._return_connection(self._mock_connection)

    @inlineCallbacks
    def test_registration(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": uuid.uuid4().hex}
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aesgcm"

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )

        ca_data = json.loads(
            self._mock_connection.request.call_args[1]['body'])
        assert response.code == 201
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        assert ca_data['chid'] == jbody['channelID']
        assert ca_data['con'] == content_encoding
        assert ca_data['cryptokey'] == crypto_key
        assert ca_data['enc'] == salt
        assert 'mutable-content' in ca_data['aps']
        assert ca_data["aps"]["alert"]["loc-key"] == \
            "SentTab.NoTabArrivingNotification.body"
        assert ca_data["aps"]["alert"]["title-loc-key"] == \
            "SentTab.NoTabArrivingNotification.title"
        assert ca_data['body'] == base64url_encode(data)

    @inlineCallbacks
    def test_apns_aesgcm_registration_bad(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": uuid.uuid4().hex}
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        content_encoding = "aesgcm"

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )
        assert response.code == 400

    @inlineCallbacks
    def test_apns_registration_aes128gcm(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": uuid.uuid4().hex}
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message

        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        content_encoding = "aes128gcm"

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )
        ca_data = json.loads(
            self._mock_connection.request.call_args[1]['body'])
        assert response.code == 201
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        assert ca_data['chid'] == jbody['channelID']
        assert ca_data['con'] == content_encoding
        assert ca_data['body'] == base64url_encode(data)
        assert 'enc' not in ca_data

    @inlineCallbacks
    def test_apns_registration_update(self):
        """Ensure that a client bridge token update does not alter other
        required elements of the registration data.

        """
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "apns",
            "firefox",
        )
        old = uuid.uuid4().hex
        new = uuid.uuid4().hex
        response, body = yield _agent('POST', url, body=json.dumps(
            {
                "chid": str(uuid.uuid4()),
                "token": old
            }
        ))
        assert response.code == 200
        jbody = json.loads(body)
        rec_old = self.ep.db.router.get_uaid(jbody['uaid'])

        response, body = yield _agent(
            'PUT',
            "{}/{}".format(url, jbody['uaid']),
            headers=Headers(
                {"authorization": ["Bearer {}".format(jbody['secret'])]}
            ),
            body=json.dumps(
                {"token": new}
            )
        )
        assert response.code == 200
        rec_new = self.ep.db.router.get_uaid(jbody['uaid'])
        assert rec_new['router_data']['token'] == new
        assert rec_new['router_data']['rel_channel'] == \
            rec_old['router_data']['rel_channel']

    @inlineCallbacks
    def test_registration_no_token(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": ''}
        ))
        assert response.code == 400

    @inlineCallbacks
    def test_registration_aps_override(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.conf.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": uuid.uuid4().hex,
             "aps": {"foo": "bar", "gorp": "baz"}
             }
        ))
        assert response.code == 200
        jbody = json.loads(body)

        # Send a fake message
        data = ("\xa2\xa5\xbd\xda\x40\xdc\xd1\xa5\xf9\x6a\x60\xa8\x57\x7b\x48"
                "\xe4\x43\x02\x5a\x72\xe0\x64\x69\xcd\x29\x6f\x65\x44\x53\x78"
                "\xe1\xd9\xf6\x46\x26\xce\x69")
        crypto_key = ("keyid=p256dh;dh=BAFJxCIaaWyb4JSkZopERL9MjXBeh3WdBxew"
                      "SYP0cZWNMJaT7YNaJUiSqBuGUxfRj-9vpTPz5ANmUYq3-u-HWOI")
        salt = "keyid=p256dh;salt=S82AseB7pAVBJ2143qtM3A"
        content_encoding = "aesgcm"

        response, body = yield _agent(
            'POST',
            str(jbody['endpoint']),
            headers=Headers({
                "crypto-key": [crypto_key],
                "encryption": [salt],
                "ttl": ["0"],
                "content-encoding": [content_encoding],
            }),
            body=data
        )

        ca_data = json.loads(
            self._mock_connection.request.call_args[1]['body'])
        assert response.code == 201
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        assert ca_data['chid'] == jbody['channelID']
        assert ca_data['con'] == content_encoding
        assert ca_data['cryptokey'] == crypto_key
        assert ca_data['enc'] == salt
        assert 'mutable-content' not in ca_data['aps']
        assert ca_data['aps']['foo'] == "bar"
        assert ca_data['body'] == base64url_encode(data)


class TestProxyProtocol(IntegrationBase):

    def endpoint_kwargs(self):
        return dict(
            super(TestProxyProtocol, self).endpoint_kwargs(),
            proxy_protocol_port=9021
        )

    @inlineCallbacks
    def test_proxy_protocol(self):
        port = self.ep.conf.proxy_protocol_port
        ip = '198.51.100.22'
        req = """\
PROXY TCP4 {} 203.0.113.7 35646 80\r
GET /v1/err HTTP/1.1\r
Host: 127.0.0.1\r
\r\n""".format(ip)

        def proxy_request():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("localhost", port))
            try:
                sock.sendall(req)
                return sock.recv(4096)
            finally:
                sock.close()

        response = yield deferToThread(proxy_request)
        assert response.startswith("HTTP/1.1 418 ")
        assert "Test Error" in response
        assert self.logs.logged_ci(lambda ci: ci.get('remote_ip') == ip)

    @inlineCallbacks
    def test_no_proxy_protocol(self):
        response, body = yield _agent(
            'GET',
            "http://localhost:{}/v1/err".format(self.ep.conf.port),
        )
        assert response.code == 418
        payload = json.loads(body)
        assert payload['error'] == "Test Error"


class TestProxyProtocolSSL(SSLEndpointMixin, IntegrationBase):

    def endpoint_kwargs(self):
        return dict(
            super(TestProxyProtocolSSL, self).endpoint_kwargs(),
            proxy_protocol_port=9021
        )

    @inlineCallbacks
    def test_proxy_protocol_ssl(self):
        ip = '198.51.100.22'

        def proxy_request():
            # like TestProxyProtocol.test_proxy_protocol, we prepend
            # the proxy proto. line before the payload (which is
            # encrypted in this case). HACK: sneak around httplib's
            # wrapped ssl sock by hooking into SSLContext.wrap_socket
            proto_line = 'PROXY TCP4 {} 203.0.113.7 35646 80\r\n'.format(ip)

            class SSLContextWrapper(object):
                def __init__(self, context):
                    self.context = context

                def wrap_socket(self, sock, *args, **kwargs):
                    # send proto_line over the raw, unencrypted sock
                    sock.send(proto_line)
                    # now do the handshake/encrypt sock
                    return self.context.wrap_socket(sock, *args, **kwargs)
            try:
                http = httplib.HTTPSConnection(
                    "localhost:{}".format(self.ep.conf.proxy_protocol_port),
                    context=SSLContextWrapper(self._create_context(None)))
            except ssl.SSLError as ex:
                if ex.reason == 'CA_MD_TOO_WEAK':
                    raise SkipTest("Old test cert in use")
                raise

            try:
                http.request('GET', '/v1/err')
                response = http.getresponse()
                return response, response.read()
            finally:
                http.close()

        response, body = yield deferToThread(proxy_request)
        assert response.status == 418
        payload = json.loads(body)
        assert payload['error'] == "Test Error"
        assert self.logs.logged_ci(lambda ci: ci.get('remote_ip') == ip)


class TestMemUsage(IntegrationBase):

    def endpoint_kwargs(self):
        return dict(
            super(TestMemUsage, self).endpoint_kwargs(),
            memusage_port=9040
        )

    @inlineCallbacks
    def test_memusage(self):
        port = self.ep.conf.memusage_port
        response, body = yield _agent(
            'GET',
            "http://localhost:{}/_memusage".format(port),
        )
        assert response.code == 200
        assert 'ru_maxrss=' in body
        assert '<malloc ' in body
        assert 'Logger' in body
        if find_executable('pmap'):
            assert 'RSS' in body or 'Rss' in body  # pmap -x or -XX/X output
        if hasattr(sys, 'pypy_version_info'):  # pragma: nocover
            assert 'size: ' in body
            assert 'rpy_string' in body, body
            assert 'get_stats_asmmemmgr: (' in body
            if sys.pypy_version_info.major >= 6:
                assert 'Total memory allocated:' in body

    @inlineCallbacks
    def test_memusage_options(self):
        port = self.ep.conf.memusage_port
        url = ("http://localhost:{}/_memusage?objgraph=false&"
               "dump_rpy_heap=false").format(port)
        response, body = yield _agent('GET', url)
        assert response.code == 200
        assert 'ru_maxrss=' in body
        assert '<malloc ' in body
        assert 'Logger' not in body
        if find_executable('pmap'):
            assert 'RSS' in body or 'Rss' in body  # pmap -x or -XX/X output
        if hasattr(sys, 'pypy_version_info'):  # pragma: nocover
            assert 'size: ' not in body
            assert 'rpy_string' not in body


@inlineCallbacks
def _agent(method, url, contextFactory=None, headers=None, body=None):
    kwargs = {}
    if contextFactory:
        kwargs['contextFactory'] = contextFactory
    agent = Agent(reactor, **kwargs)
    rbody = None
    if body:
        rbody = FileBodyProducer(StringIO(body))
    response = yield agent.request(method, url,
                                   headers=headers,
                                   bodyProducer=rbody)

    proto = AccumulatingProtocol()
    proto.closedDeferred = Deferred()
    response.deliverBody(proto)
    yield proto.closedDeferred

    returnValue((response, proto.data))
