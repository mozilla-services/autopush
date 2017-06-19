import httplib
import json
import logging
import os
import random
import signal
import subprocess
import sys
import time
import urlparse
import uuid
from contextlib import contextmanager
from distutils.spawn import find_executable
from StringIO import StringIO
from httplib import HTTPResponse  # noqa
from unittest.case import SkipTest

from zope.interface import implementer

import boto
import ecdsa
import psutil
import twisted.internet.base
import websocket
from cryptography.fernet import Fernet
from jose import jws
from nose.tools import eq_, ok_
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
from autopush.db import (
    create_rotating_message_table,
    get_month,
    has_connected_this_month
)
from autopush.logging import begin_or_register
from autopush.main import ConnectionApplication, EndpointApplication
from autopush.settings import AutopushSettings
from autopush.utils import base64url_encode
from autopush.metrics import SinkMetrics
from autopush.tests.support import TestingLogObserver
from autopush.websocket import PushServerFactory

log = logging.getLogger(__name__)
here_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.dirname(os.path.dirname(here_dir))
ddb_dir = os.path.join(root_dir, "ddb")
ddb_lib_dir = os.path.join(ddb_dir, "DynamoDBLocal_lib")
ddb_jar = os.path.join(ddb_dir, "DynamoDBLocal.jar")
ddb_process = None

twisted.internet.base.DelayedCall.debug = True


def setUp():
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    boto_path = os.path.join(root_dir, "automock", "boto.cfg")
    boto.config.load_from_path(boto_path)
    if "SKIP_INTEGRATION" in os.environ:  # pragma: nocover
        raise SkipTest("Skipping integration tests")
    global ddb_process
    cmd = " ".join([
        "java", "-Djava.library.path=%s" % ddb_lib_dir,
        "-jar", ddb_jar, "-sharedDb", "-inMemory"
    ])
    ddb_process = subprocess.Popen(cmd, shell=True, env=os.environ)

    # Setup the necessary message tables
    message_table = os.environ.get("MESSAGE_TABLE", "message_int_test")
    create_rotating_message_table(prefix=message_table, delta=-1)
    create_rotating_message_table(prefix=message_table)


def tearDown():
    global ddb_process
    # This kinda sucks, but its the only way to nuke the child procs
    proc = psutil.Process(pid=ddb_process.pid)
    child_procs = proc.children(recursive=True)
    for p in [proc] + child_procs:
        os.kill(p.pid, signal.SIGTERM)
    ddb_process.wait()

    # Clear out the boto config that was loaded so the rest of the tests run
    # fine
    for section in boto.config.sections():
        boto.config.remove_section(section)


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
    def __init__(self, url, use_webpush=False, sslcontext=None):
        self.url = url
        self.uaid = None
        self.ws = None
        self.use_webpush = use_webpush
        self.channels = {}
        self.messages = {}
        self.notif_response = None  # type: Optional[HTTPResponse]
        self._crypto_key = """\
keyid="http://example.org/bob/keys/123;salt="XZwpw6o37R-6qoZjw6KwAw"\
"""
        self.sslcontext = sslcontext

    def __getattribute__(self, name):
        # Python fun to turn all functions into deferToThread functions
        f = object.__getattribute__(self, name)
        if name.startswith("__"):
            return f

        if callable(f):
            return lambda *args, **kwargs: deferToThread(f, *args, **kwargs)
        else:
            return f

    def connect(self):
        self.ws = websocket.create_connection(self.url)
        return self.ws.connected

    def hello(self, uaid=None):
        if self.channels:
            chans = self.channels.keys()
        else:
            chans = []
        hello_dict = dict(messageType="hello", uaid=uaid or self.uaid or "",
                          channelIDs=chans)
        if self.use_webpush:
            hello_dict["use_webpush"] = True
        msg = json.dumps(hello_dict)
        log.debug("Send: %s", msg)
        self.ws.send(msg)
        result = json.loads(self.ws.recv())
        log.debug("Recv: %s", result)
        if self.uaid and self.uaid != result["uaid"]:  # pragma: nocover
            log.debug("Mismatch on re-using uaid. Old: %s, New: %s",
                      self.uaid, result["uaid"])
            self.channels = {}
        self.uaid = result["uaid"]
        eq_(result["status"], 200)
        return result

    def register(self, chid=None, key=None):
        chid = chid or str(uuid.uuid4())
        msg = json.dumps(dict(messageType="register",
                              channelID=chid,
                              key=key))
        log.debug("Send: %s", msg)
        self.ws.send(msg)
        result = json.loads(self.ws.recv())
        log.debug("Recv: %s", result)
        eq_(result["status"], 200)
        eq_(result["channelID"], chid)
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
        eq_(resp.status, status)

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

        if self.use_webpush:
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
        else:
            if data:
                body = "version=%s&data=%s" % (version or "", data)
            else:
                body = "version=%s" % (version or "")
            if use_header:
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
            else:
                headers = {}
            method = "PUT"
            if not status:
                status = 200

        log.debug("%s body: %s", method, body)
        http.request(method, url.path.encode("utf-8"), body, headers)
        resp = http.getresponse()
        log.debug("%s Response (%s): %s", method, resp.status, resp.read())
        http.close()
        eq_(resp.status, status)
        self.notif_response = resp
        location = resp.getheader("Location", None)
        log.debug("Response Headers: %s", resp.getheaders())
        if self.use_webpush:
            if status >= 200 and status < 300:
                ok_(location is not None)
            if status == 201 and ttl is not None:
                ttl_header = resp.getheader("TTL")
                eq_(ttl_header, str(ttl))
            if ttl != 0 and status == 201:
                ok_(location is not None)
                if channel in self.messages:
                    self.messages[channel].append(location)
                else:
                    self.messages[channel] = [location]
        else:
            # Simple Push messages are not individually addressable.
            ok_(location is None)

        # Pull the notification if connected
        if self.ws and self.ws.connected:
            return object.__getattribute__(self, "get_notification")(timeout)

    def get_notification(self, timeout=1):
        orig_timeout = self.ws.gettimeout()
        self.ws.settimeout(timeout)
        try:
            d = self.ws.recv()
            log.debug("Recv: %s", d)
            return json.loads(d)
        except:
            return None
        finally:
            self.ws.settimeout(orig_timeout)

    def ping(self):
        log.debug("Send: %s", "{}")
        self.ws.send("{}")
        result = self.ws.recv()
        log.debug("Recv: %s", result)
        eq_(result, "{}")
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
STORAGE_TABLE = os.environ.get("STORAGE_TABLE", "storage_int_test")
MESSAGE_TABLE = os.environ.get("MESSAGE_TABLE", "message_int_test")


class IntegrationBase(unittest.TestCase):
    track_objects = True
    track_objects_excludes = [AutopushSettings, PushServerFactory]

    endpoint_port = 9020

    _endpoint_defaults = dict(
        hostname='localhost',
        port=endpoint_port,
        endpoint_port=endpoint_port,
        endpoint_scheme='http',
        statsd_host=None,
        router_tablename=ROUTER_TABLE,
        storage_tablename=STORAGE_TABLE,
        message_tablename=MESSAGE_TABLE,
    )

    _conn_defaults = dict(
        hostname='localhost',
        port=9010,
        endpoint_port=endpoint_port,
        router_port=9030,
        endpoint_scheme='http',
        statsd_host=None,
        router_tablename=ROUTER_TABLE,
        storage_tablename=STORAGE_TABLE,
        message_tablename=MESSAGE_TABLE,
    )

    def setUp(self):
        self.logs = TestingLogObserver()
        begin_or_register(self.logs)
        self.addCleanup(globalLogPublisher.removeObserver, self.logs)

        crypto_key = Fernet.generate_key()
        ep_settings = AutopushSettings(
            crypto_key=crypto_key,
            **self.endpoint_kwargs()
        )
        conn_settings = AutopushSettings(
            crypto_key=crypto_key,
            **self.conn_kwargs()
        )
        # Dirty reactor unless we shut down the cached connections
        self.addCleanup(ep_settings.agent._pool.closeCachedConnections)
        self.addCleanup(conn_settings.agent._pool.closeCachedConnections)

        # Endpoint HTTP router
        self.ep = ep = EndpointApplication(ep_settings)
        ep.setup(rotate_tables=False)
        ep.startService()
        self.addCleanup(ep.stopService)

        # Websocket server
        self.conn = conn = ConnectionApplication(conn_settings)
        conn.setup(rotate_tables=False)
        conn.startService()
        self.addCleanup(conn.stopService)

    def endpoint_kwargs(self):
        return self._endpoint_defaults

    def conn_kwargs(self):
        return self._conn_defaults

    @inlineCallbacks
    def quick_register(self, use_webpush=False, sslcontext=None):
        client = Client("ws://localhost:9010/",
                        use_webpush=use_webpush,
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
        self.ep.settings._notification_legacy = True
        yield
        self.ep.settings._notification_legacy = False


class SSLEndpointMixin(object):

    certs = os.path.join(os.path.dirname(__file__), "certs")
    servercert = os.path.join(certs, "server.pem")

    def endpoint_kwargs(self):
        return dict(
            super(SSLEndpointMixin, self).endpoint_kwargs(),
            ssl_key=self.servercert,
            ssl_cert=self.servercert,
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


class TestSimple(IntegrationBase):
    @inlineCallbacks
    def test_delivery_while_disconnected(self):
        client = yield self.quick_register()
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(len(result["updates"]), 1)
        eq_(result["updates"][0]["channelID"], chan)
        yield self.shut_down(client)
        log_event = self.logs.logged_session()
        eq_(log_event["connection_type"], "simplepush")
        eq_(log_event["direct_acked"], 0)

    @inlineCallbacks
    def test_delivery_repeat_without_ack(self):
        client = yield self.quick_register()
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(len(result["updates"]), 1)
        eq_(result["updates"][0]["channelID"], chan)

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["updates"] > 0)
        eq_(result["updates"][0]["channelID"], chan)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_direct_delivery_without_ack(self):
        client = yield self.quick_register()
        result = yield client.send_notification()
        ok_(result != {})
        yield client.disconnect()
        log_event = self.logs.logged_session()
        eq_(log_event["direct_acked"], 0)
        eq_(log_event["direct_storage"], 1)

        yield client.connect()
        yield client.hello()
        result2 = yield client.get_notification(timeout=5)
        ok_(result2 != {})
        update1 = result["updates"][0]
        if 'data' in update1:
            del update1["data"]
        update2 = result2["updates"][0]
        eq_(update1, update2)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_dont_deliver_acked(self):
        client = yield self.quick_register()
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        update = result["updates"][0]
        eq_(update["channelID"], chan)
        yield client.ack(chan, update["version"])
        yield client.disconnect()
        log_event = self.logs.logged_session()
        eq_(log_event["connection_type"], "simplepush")
        eq_(log_event["stored_acked"], 1)

        time.sleep(0.2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)
        log_event = self.logs.logged_session()
        eq_(log_event["connection_type"], "simplepush")
        eq_(log_event["stored_acked"], 0)

    @inlineCallbacks
    def test_no_delivery_to_unregistered(self):
        client = yield self.quick_register()
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        update = result["updates"][0]
        eq_(update["channelID"], chan)

        yield client.unregister(chan)
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_deliver_version(self):
        client = yield self.quick_register()
        result = yield client.send_notification(version=12)
        ok_(result is not None)
        eq_(result["updates"][0]["version"], 12)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_deliver_version_without_header(self):
        client = yield self.quick_register()
        result = yield client.send_notification(version=12, use_header=False)
        ok_(result is not None)
        eq_(result["updates"][0]["version"], 12)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_last_connect(self):
        client = yield self.quick_register()
        yield client.disconnect()

        # Verify the last_connect is there and the current month
        c = yield deferToThread(
            self.conn.settings.router.get_uaid, client.uaid)
        eq_(True, has_connected_this_month(c))

        # Move it back
        today = get_month(delta=-1)
        c["last_connect"] = "%s%s020001" % (today.year,
                                            str(today.month).zfill(2))
        yield deferToThread(c.partial_save)
        eq_(False, has_connected_this_month(c))

        # Connect/disconnect again and verify last_connect move
        yield client.connect()
        yield client.hello()
        yield client.disconnect()
        times = 0
        while times < 10:
            c = yield deferToThread(
                self.conn.settings.router.get_uaid, client.uaid)
            if has_connected_this_month(c):
                break
            else:  # pragma: nocover
                times += 1
                yield client.sleep(1)
        log.debug("Last connected time: %s", c.get("last_connect", "None"))
        eq_(True, has_connected_this_month(c))

    @inlineCallbacks
    def test_endpoint_client_info(self):
        client = yield self.quick_register()
        result = yield client.send_notification()
        ok_(result is not None)
        ok_(self.logs.logged_ci(
            lambda ci: ci['python_version'] == sys.version))
        yield self.shut_down(client)


class TestData(IntegrationBase):
    @inlineCallbacks
    def test_simplepush_data_delivery(self):
        client = yield self.quick_register()
        result = yield client.send_notification(data="howdythere")
        ok_(result is not None)
        eq_(result["updates"][0]["data"], "howdythere")
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_data_delivery_to_connected_client(self):
        client = yield self.quick_register(use_webpush=True)
        ok_(client.channels)
        chan = client.channels.keys()[0]

        # Invalid UTF-8 byte sequence.
        data = b"\xc3\x28\xa0\xa1\xe2\x28\xa1"

        result = yield client.send_notification(data=data)
        ok_(result is not None)
        eq_(result["messageType"], "notification")
        eq_(result["channelID"], chan)
        eq_(result["data"], "wyigoeIooQ")
        ok_(self.logs.logged_ci(lambda ci: 'message_size' in ci),
            "message_size not logged")
        ok_(self.logs.logged_ci(
            lambda ci: ci['encoding'] == "aesgcm"
        ))
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_data_delivery_to_disconnected_client(self):
        tests = {
            "d248d4e0-0ef4-41d9-8db5-2533ad8e4041": dict(
                data=b"\xe2\x82\x28\xf0\x28\x8c\xbc", result="4oIo8CiMvA"),

            "df2363be-4d55-49c5-a1e3-aeae9450692e": dict(
                data=b"\xf0\x90\x28\xbc\xf0\x28\x8c\x28",
                result="8JAovPAojCg"),

            "6c33e055-5762-47e5-b90c-90ad9bfe3f53": dict(
                data=b"\xc3\x28\xa0\xa1\xe2\x28\xa1", result="wyigoeIooQ"),
        }

        client = Client("ws://localhost:9010/", use_webpush=True)
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
            ok_(result is not None)
            chan = result["channelID"]
            test = tests[chan]
            eq_(result["data"], test["result"])
            headers = result["headers"]
            ok_("crypto_key" in headers)
            ok_("encryption" in headers)
            ok_("encoding" in headers)
            yield client.ack(chan, result["version"])

        ok_(self.logs.logged_ci(lambda ci: 'message_size' in ci),
            "message_size not logged")
        yield self.shut_down(client)

    @inlineCallbacks
    def test_data_delivery_without_header(self):
        client = yield self.quick_register()
        result = yield client.send_notification(data="howdythere",
                                                use_header=False)
        ok_(result is not None)
        eq_(result["updates"][0]["data"], "howdythere")
        yield self.shut_down(client)


class TestLoop(IntegrationBase):
    @inlineCallbacks
    def test_basic_deliver(self):
        client = yield self.quick_register()
        result = yield client.send_notification()
        ok_(result != {})
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
        ok_(result != {})
        ok_(result["updates"] > 0)
        eq_(result["updates"][0]["channelID"], chan)
        yield self.shut_down(client)


class TestWebPush(IntegrationBase):

    @property
    def _ws_url(self):
        return self.conn.settings.ws_url

    @inlineCallbacks
    def test_hello_only_has_three_calls(self):
        db.TRACK_DB_CALLS = True
        client = Client(self._ws_url, use_webpush=True)
        yield client.connect()
        result = yield client.hello()
        ok_(result != {})
        eq_(result["use_webpush"], True)
        yield client.wait_for(lambda: len(db.DB_CALLS) == 3)
        eq_(db.DB_CALLS, ['register_user', 'fetch_messages',
                          'fetch_timestamp_messages'])
        db.DB_CALLS = []
        db.TRACK_DB_CALLS = False

        yield self.shut_down(client)

    @inlineCallbacks
    def test_hello_echo(self):
        client = Client(self._ws_url, use_webpush=True)
        yield client.connect()
        result = yield client.hello()
        ok_(result != {})
        eq_(result["use_webpush"], True)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_hello_with_bad_prior_uaid(self):
        non_uaid = uuid.uuid4().hex
        client = Client(self._ws_url, use_webpush=True)
        yield client.connect()
        result = yield client.hello(uaid=non_uaid)
        ok_(result != {})
        ok_(result["uaid"] != non_uaid)
        eq_(result["use_webpush"], True)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        yield self.shut_down(client)
        log_event = self.logs.logged_session()
        eq_(log_event["connection_type"], "webpush")
        eq_(log_event["direct_storage"], 1)

    @inlineCallbacks
    def test_topic_basic_delivery(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, topic="Inbox")
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        yield self.shut_down(client)

    @inlineCallbacks
    def test_topic_replacement_delivery(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        yield client.send_notification(data=data, topic="Inbox")
        yield client.send_notification(data=data2, topic="Inbox")
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data2))
        eq_(result["messageType"], "notification")
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_topic_no_delivery_on_reconnect(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        yield client.send_notification(data=data, topic="Inbox")
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification(timeout=10)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        yield client.ack(result["channelID"], result["version"])
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_vapid(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        vapid_info = _get_vapid()
        result = yield client.send_notification(data=data, vapid=vapid_info)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        ok_(self.logs.logged_ci(lambda ci: 'router_key' in ci),
            "router_key not logged")
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_invalid_vapid(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
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
        client = yield self.quick_register(use_webpush=True)
        vapid_info = _get_vapid(
            payload={"aud": "https://pusher_origin.example.com",
                     "exp": '@',
                     "sub": "mailto:admin@example.com"})
        vapid_info['crypto-key'] = "invalid"
        yield client.send_notification(
            data=data,
            vapid=vapid_info,
            status=401)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery_with_invalid_vapid_auth(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
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
        client = yield self.quick_register(use_webpush=True)
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
        client = yield self.quick_register(use_webpush=True)
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
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(result["data"], base64url_encode(data))

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(result["data"], base64url_encode(data))
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_delivery_repeat_without_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data)
        yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_legacy_delivery_with_single_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        with self.legacy_endpoint():
            yield client.send_notification(data=data)
            yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification(timeout=5)
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))
        ok_(result["messageType"], "notification")
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_delivery_with_single_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data)
        yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(result["data"], base64url_encode(data))
        result2 = yield client.get_notification()
        ok_(result2 != {})
        eq_(result2["data"], base64url_encode(data2))
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(result["data"], base64url_encode(data))
        ok_(result["messageType"], "notification")
        result2 = yield client.get_notification()
        ok_(result2 != {})
        eq_(result2["data"], base64url_encode(data2))
        yield client.ack(result2["channelID"], result2["version"])

        # Verify no messages are delivered
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result is None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_multiple_delivery_with_multiple_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data)
        yield client.send_notification(data=data2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(base64url_encode, [data, data2]))
        result2 = yield client.get_notification()
        ok_(result2 != {})
        ok_(result2["data"] in map(base64url_encode, [data, data2]))
        yield client.ack(result2["channelID"], result2["version"])
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_no_delivery_to_unregistered(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)  # type: Client
        ok_(client.channels)
        chan = client.channels.keys()[0]

        result = yield client.send_notification(data=data)
        eq_(result["channelID"], chan)
        eq_(result["data"], base64url_encode(data))
        yield client.ack(result["channelID"], result["version"])

        yield client.unregister(chan)
        result = yield client.send_notification(data=data, status=410)

        # Verify cache-control
        eq_(client.notif_response.getheader("Cache-Control"), "max-age=86400")

        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_not_present_not_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        yield client.send_notification(data=data, ttl=None, status=400)
        self.flushLoggedErrors()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_not_present_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, ttl=None)
        ok_(result is not None)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_not_present_connected_no_ack(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, ttl=None)
        ok_(result is not None)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_0_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, ttl=0)
        ok_(result is not None)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_0_not_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        yield client.send_notification(data=data, ttl=0)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_expired(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        yield client.send_notification(data=data, ttl=1)
        time.sleep(1.5)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_batch_expired_and_good_one(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        for x in range(0, 12):
            yield client.send_notification(data=data, ttl=1)

        yield client.send_notification(data=data2)
        time.sleep(1.5)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification(timeout=4)
        ok_(result is not None)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data2))
        eq_(result["messageType"], "notification")
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_batch_partly_expired_and_good_one(self):
        data = str(uuid.uuid4())
        data1 = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
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
            ok_(result is not None)
            eq_(result["data"], base64url_encode(data))
            yield client.ack(result["channelID"], result["version"])

        # Should have one more that is data2, this will only arrive if the
        # other six were acked as that hits the batch size
        result = yield client.get_notification(timeout=4)
        ok_(result is not None)
        eq_(result["data"], base64url_encode(data2))

        # No more
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_message_without_crypto_headers(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, use_header=False,
                                                status=400)
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_message_with_topic(self):
        from mock import Mock, call
        data = str(uuid.uuid4())
        self.conn.settings.metrics = Mock(spec=SinkMetrics)
        client = yield self.quick_register(use_webpush=True)
        yield client.send_notification(data=data, topic="topicname")
        self.conn.settings.metrics.increment.assert_has_calls([
            call('updates.notification.topic',
                 tags=['host:localhost', 'use_webpush:True'])
        ])
        yield self.shut_down(client)

    @inlineCallbacks
    def test_empty_message_without_crypto_headers(self):
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(use_header=False)
        ok_(result is not None)
        eq_(result["messageType"], "notification")
        ok_("headers" not in result)
        ok_("data" not in result)
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.send_notification(use_header=False)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result is not None)
        ok_("headers" not in result)
        ok_("data" not in result)
        yield client.ack(result["channelID"], result["version"])

        yield self.shut_down(client)

    @inlineCallbacks
    def test_empty_message_with_crypto_headers(self):
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification()
        ok_(result is not None)
        eq_(result["messageType"], "notification")
        ok_("headers" not in result)
        ok_("data" not in result)

        result2 = yield client.send_notification()
        # We shouldn't store headers for blank messages.
        ok_(result2 is not None)
        eq_(result2["messageType"], "notification")
        ok_("headers" not in result2)
        ok_("data" not in result2)

        yield client.ack(result["channelID"], result["version"])
        yield client.ack(result2["channelID"], result2["version"])

        yield client.disconnect()
        yield client.send_notification()
        yield client.connect()
        yield client.hello()
        result3 = yield client.get_notification()
        ok_(result3 is not None)
        ok_("headers" not in result3)
        ok_("data" not in result3)
        yield client.ack(result3["channelID"], result3["version"])

        yield self.shut_down(client)

    @inlineCallbacks
    def test_delete_saved_notification(self):
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification()
        yield client.delete_notification(chan)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_monthly_rotation(self):
        from autopush.db import make_rotating_tablename
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()

        # Move the client back one month to the past
        last_month = make_rotating_tablename(
            prefix=self.conn.settings._message_prefix, delta=-1)
        lm_message = self.conn.settings.message_tables[last_month]
        yield deferToThread(
            self.conn.settings.router.update_message_month,
            client.uaid,
            last_month
        )

        # Verify the move
        c = yield deferToThread(
            self.conn.settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], last_month)

        # Verify last_connect is current, then move that back
        ok_(has_connected_this_month(c))
        today = get_month(delta=-1)
        c["last_connect"] = "%s%s020001" % (today.year,
                                            str(today.month).zfill(2))
        yield deferToThread(c.partial_save)
        eq_(False, has_connected_this_month(c))

        # Move the clients channels back one month
        exists, chans = yield deferToThread(
            self.conn.settings.message.all_channels, client.uaid
        )
        eq_(exists, True)
        eq_(len(chans), 1)
        yield deferToThread(
            lm_message.save_channels,
            client.uaid,
            chans
        )

        # Remove the channels entry entirely from this month
        yield deferToThread(self.conn.settings.message.table.delete_item,
                            uaid=client.uaid,
                            chidmessageid=" "
                            )

        # Verify the channel is gone
        exists, chans = yield deferToThread(
            self.conn.settings.message.all_channels,
            client.uaid
        )
        eq_(exists, False)
        eq_(len(chans), 0)

        # Send in a notification, verify it landed in last months notification
        # table
        data = uuid.uuid4().hex
        with self.legacy_endpoint():
            yield client.send_notification(data=data)
        ts, notifs = yield deferToThread(lm_message.fetch_timestamp_messages,
                                         uuid.UUID(client.uaid),
                                         " ")
        eq_(len(notifs), 1)

        # Connect the client, verify the migration
        yield client.connect()
        yield client.hello()

        # Pull down the notification
        result = yield client.get_notification()
        chan = client.channels.keys()[0]
        ok_(result is not None)
        eq_(chan, result["channelID"])

        # Check that the client is going to rotate the month
        server_client = self.conn.settings.clients[client.uaid]
        eq_(server_client.ps.rotate_message_table, True)

        # Acknowledge the notification, which triggers the migration
        yield client.ack(chan, result["version"])

        # Wait up to 2 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 2:
            c = yield deferToThread(
                self.conn.settings.router.get_uaid, client.uaid)
            if c["current_month"] == self.conn.settings.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(
            self.conn.settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], self.conn.settings.current_msg_month)
        eq_(server_client.ps.rotate_message_table, False)

        # Verify the client moved last_connect
        eq_(True, has_connected_this_month(c))

        # Verify the channels were moved
        exists, chans = yield deferToThread(
            self.conn.settings.message.all_channels,
            client.uaid
        )
        eq_(exists, True)
        eq_(len(chans), 1)

        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_monthly_rotation_prior_record_exists(self):
        from autopush.db import make_rotating_tablename
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()

        # Move the client back one month to the past
        last_month = make_rotating_tablename(
            prefix=self.conn.settings._message_prefix, delta=-1)
        lm_message = self.conn.settings.message_tables[last_month]
        yield deferToThread(
            self.conn.settings.router.update_message_month,
            client.uaid,
            last_month
        )

        # Verify the move
        c = yield deferToThread(
            self.conn.settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], last_month)

        # Verify last_connect is current, then move that back
        ok_(has_connected_this_month(c))
        today = get_month(delta=-1)
        c["last_connect"] = "%s%s020001" % (today.year,
                                            str(today.month).zfill(2))
        yield deferToThread(c.partial_save)
        eq_(False, has_connected_this_month(c))

        # Move the clients channels back one month
        exists, chans = yield deferToThread(
            self.conn.settings.message.all_channels, client.uaid
        )
        eq_(exists, True)
        eq_(len(chans), 1)
        yield deferToThread(
            lm_message.save_channels,
            client.uaid,
            chans
        )

        # Send in a notification, verify it landed in last months notification
        # table
        data = uuid.uuid4().hex
        with self.legacy_endpoint():
            yield client.send_notification(data=data)
        _, notifs = yield deferToThread(lm_message.fetch_timestamp_messages,
                                        uuid.UUID(client.uaid),
                                        " ")
        eq_(len(notifs), 1)

        # Connect the client, verify the migration
        yield client.connect()
        yield client.hello()

        # Pull down the notification
        result = yield client.get_notification()
        chan = client.channels.keys()[0]
        ok_(result is not None)
        eq_(chan, result["channelID"])

        # Check that the client is going to rotate the month
        server_client = self.conn.settings.clients[client.uaid]
        eq_(server_client.ps.rotate_message_table, True)

        # Acknowledge the notification, which triggers the migration
        yield client.ack(chan, result["version"])

        # Wait up to 2 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 2:
            c = yield deferToThread(
                self.conn.settings.router.get_uaid, client.uaid)
            if c["current_month"] == self.conn.settings.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(
            self.conn.settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], self.conn.settings.current_msg_month)
        eq_(server_client.ps.rotate_message_table, False)

        # Verify the client moved last_connect
        eq_(True, has_connected_this_month(c))

        # Verify the channels were moved
        exists, chans = yield deferToThread(
            self.conn.settings.message.all_channels,
            client.uaid
        )
        eq_(exists, True)
        eq_(len(chans), 1)

        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_monthly_rotation_no_channels(self):
        from autopush.db import make_rotating_tablename
        client = Client("ws://localhost:9010/", use_webpush=True)
        yield client.connect()
        yield client.hello()
        yield client.disconnect()

        # Move the client back one month to the past
        last_month = make_rotating_tablename(
            prefix=self.conn.settings._message_prefix, delta=-1)
        yield deferToThread(
            self.conn.settings.router.update_message_month,
            client.uaid,
            last_month
        )

        # Verify the move
        c = yield deferToThread(
            self.conn.settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], last_month)

        # Verify there's no channels
        exists, chans = yield deferToThread(
            self.conn.settings.message.all_channels,
            client.uaid
        )
        eq_(exists, False)
        eq_(len(chans), 0)

        # Connect the client, verify the migration
        yield client.connect()
        yield client.hello()

        # Check that the client is going to rotate the month
        server_client = self.conn.settings.clients[client.uaid]
        eq_(server_client.ps.rotate_message_table, True)

        # Wait up to 2 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 2:
            c = yield deferToThread(
                self.conn.settings.router.get_uaid, client.uaid)
            if c["current_month"] == self.conn.settings.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(
            self.conn.settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], self.conn.settings.current_msg_month)
        eq_(server_client.ps.rotate_message_table, False)

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
        client = Client("ws://localhost:9010/", use_webpush=True)
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
    def test_client_cert_simple(self):
        client = yield self.quick_register(
            sslcontext=self._create_context(self.auth_client))
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(len(result["updates"]), 1)
        eq_(result["updates"][0]["channelID"], chan)

        certs = self._client_certs
        ok_(self.logs.logged_ci(
            lambda ci: ('tls_auth' in ci and
                        certs[ci['tls_auth_sha256']] == ci['tls_auth'] and
                        ci['tls_auth_cn'] == 'localhost')
        ))

        yield self.shut_down(client)

    @inlineCallbacks
    def test_client_cert_webpush(self):
        client = yield self.quick_register(
            use_webpush=True,
            sslcontext=self._create_context(self.auth_client))
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]

        yield client.send_notification()
        yield client.delete_notification(chan)
        result = yield client.get_notification()
        eq_(result, None)

        yield self.shut_down(client)

    @inlineCallbacks
    def test_client_cert_unauth(self):
        yield self._test_unauth(self.unauth_client)

    @inlineCallbacks
    def test_no_client_cert(self):
        yield self._test_unauth(None)

    @inlineCallbacks
    def _test_unauth(self, certfile):
        client = yield self.quick_register(
            sslcontext=self._create_context(certfile))
        yield client.disconnect()
        yield client.send_notification(status=401)
        ok_(self.logs.logged(
            lambda e: (e['log_format'] == "Failed TLS auth" and
                       (not certfile or
                        e['client_info']['tls_failed_cn'] == 'localhost'))
        ))

        response, body = yield _agent(
            'DELETE',
            "https://localhost:9020/m/foo",
            contextFactory=self.client_SSLCF(certfile))
        eq_(response.code, 401)
        wwwauth = response.headers.getRawHeaders('www-authenticate')
        eq_(wwwauth, ['Transport mode="tls-client-certificate"'])

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
        eq_(response.code, 418)
        payload = json.loads(body)
        eq_(payload['error'], "Test Error")

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
        eq_(response.code, 200)
        payload = json.loads(body)
        eq_(payload, dict(status="OK", version=__version__))

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
        eq_(response.code, 200)
        payload = json.loads(body)
        eq_(payload['version'], __version__)


class TestHealth(IntegrationBase):
    @inlineCallbacks
    def test_status(self):
        response, body = yield _agent('GET', "http://localhost:9010/status")
        eq_(response.code, 200)
        payload = json.loads(body)
        eq_(payload, dict(status="OK", version=__version__))


class TestGCMBridgeIntegration(IntegrationBase):

    senderID = "1009375523940"

    class MockReply(object):
        success = dict()
        canonical = dict()
        failed_items = dict()
        not_registered = dict()
        failed = dict()
        _needs_retry = False

        @classmethod
        def needs_retry(cls=None):
            return False

    def _add_router(self):
        from autopush.router.gcm import GCMRouter
        from mock import Mock
        gcm = GCMRouter(
            self.ep.settings,
            {
                "ttl": 0,
                "dryrun": True,
                "max_data": 4096,
                "collapsekey": "test",
                "senderIDs": {self.senderID:
                              {"auth": "AIzaSyCx9PRtH8ByaJR3Cf"
                                       "Jamz0D2N0uaCgRGiI"}}
            }
        )
        self.ep.settings.routers["gcm"] = gcm
        # Set up the mock call to avoid calling the live system.
        # The problem with calling the live system (even sandboxed) is that
        # you need a valid credential set from a mobile device, which can be
        # subject to change.
        self._mock_send = Mock()
        self._mock_reply = self.MockReply
        self._mock_send.return_value = self._mock_reply
        gcm.gcm[self.senderID].send = self._mock_send

    @inlineCallbacks
    def test_registration(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.settings.endpoint_url,
            "gcm",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"chid": str(uuid.uuid4()),
             "token": uuid.uuid4().hex,
             }
        ))
        eq_(response.code, 200)
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

        ca_data = self._mock_send.call_args[0][0].data
        eq_(response.code, 201)
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        eq_(ca_data['chid'], jbody['channelID'])
        eq_(ca_data['con'], content_encoding)
        eq_(ca_data['cryptokey'], crypto_key)
        eq_(ca_data['enc'], salt)
        eq_(ca_data['body'], base64url_encode(data))

    @inlineCallbacks
    def test_registration_no_token(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.settings.endpoint_url,
            "gcm",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {
                "chid": str(uuid.uuid4()),
                "token": '',
             }
        ))
        eq_(response.code, 400)


class TestFCMBridgeIntegration(IntegrationBase):

    senderID = "1009375523940"

    def _add_router(self):
        from autopush.router.fcm import FCMRouter
        from mock import Mock
        fcm = FCMRouter(
            self.ep.settings,
            {
                "ttl": 0,
                "dryrun": True,
                "max_data": 4096,
                "collapsekey": "test",
                "senderID": self.senderID,
                "auth": "AIzaSyCx9PRtH8ByaJR3CfJamz0D2N0uaCgRGiI",
            }
        )
        self.ep.settings.routers["fcm"] = fcm
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
        fcm.fcm.send_request = self._mock_send
        fcm.fcm.parse_responses = Mock(return_value=[reply])

    @inlineCallbacks
    def test_registration(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.settings.endpoint_url,
            "fcm",
            self.senderID,
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"chid": str(uuid.uuid4()),
             "token": uuid.uuid4().hex,
             }
        ))
        eq_(response.code, 200)
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
        eq_(response.code, 201)
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        eq_(ca_data['chid'], jbody['channelID'])
        eq_(ca_data['con'], content_encoding)
        eq_(ca_data['cryptokey'], crypto_key)
        eq_(ca_data['enc'], salt)
        eq_(ca_data['body'], base64url_encode(data))


class TestAPNSBridgeIntegration(IntegrationBase):

    class m_response:
        status = 200

    def _add_router(self):
        from autopush.router.apnsrouter import APNSRouter
        from mock import Mock
        apns = APNSRouter(
            self.ep.settings, {
                "firefox": {
                    "cert": "/home/user/certs/SimplePushDemo.p12_cert.pem",
                    "key": "/home/user/certs/SimplePushDemo.p12_key.pem",
                    "sandbox": True,
                }
            },
            load_connections=False,)
        self.ep.settings.routers["apns"] = apns
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
            self.ep.settings.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": uuid.uuid4().hex}
        ))
        eq_(response.code, 200)
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
        eq_(response.code, 201)
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        eq_(ca_data['chid'], jbody['channelID'])
        eq_(ca_data['con'], content_encoding)
        eq_(ca_data['cryptokey'], crypto_key)
        eq_(ca_data['enc'], salt)
        ok_('mutable-content' in ca_data['aps'])
        eq_(ca_data['aps']['alert']['title'], " ")
        eq_(ca_data['aps']['alert']['body'], " ")
        eq_(ca_data['body'], base64url_encode(data))

    @inlineCallbacks
    def test_registration_no_token(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.settings.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": ''}
        ))
        eq_(response.code, 400)

    @inlineCallbacks
    def test_registration_aps_override(self):
        self._add_router()
        # get the senderid
        url = "{}/v1/{}/{}/registration".format(
            self.ep.settings.endpoint_url,
            "apns",
            "firefox",
        )
        response, body = yield _agent('POST', url, body=json.dumps(
            {"token": uuid.uuid4().hex,
             "aps": {"foo": "bar", "gorp": "baz"}
             }
        ))
        eq_(response.code, 200)
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
        eq_(response.code, 201)
        # ChannelID here MUST match what we got from the registration call.
        # Currently, this is a lowercase, hex UUID without dashes.
        eq_(ca_data['chid'], jbody['channelID'])
        eq_(ca_data['con'], content_encoding)
        eq_(ca_data['cryptokey'], crypto_key)
        eq_(ca_data['enc'], salt)
        ok_('mutable-content' not in ca_data['aps'])
        eq_(ca_data['aps']['foo'], "bar")
        eq_(ca_data['body'], base64url_encode(data))


class TestProxyProtocol(IntegrationBase):

    def endpoint_kwargs(self):
        return dict(
            super(TestProxyProtocol, self).endpoint_kwargs(),
            proxy_protocol_port=9021
        )

    @inlineCallbacks
    def test_proxy_protocol(self):
        port = self.ep.settings.proxy_protocol_port
        ip = '198.51.100.22'
        proto_line = 'PROXY TCP4 {} 203.0.113.7 35646 80\r\n'.format(ip)
        # the proxy proto. line comes before the request: we can sneak
        # it in before the verb
        response, body = yield _agent(
            '{}GET'.format(proto_line),
            "http://localhost:{}/v1/err".format(port),
        )
        eq_(response.code, 418)
        payload = json.loads(body)
        eq_(payload['error'], "Test Error")
        ok_(self.logs.logged_ci(lambda ci: ci.get('remote_ip') == ip))

    @inlineCallbacks
    def test_no_proxy_protocol(self):
        response, body = yield _agent(
            'GET',
            "http://localhost:{}/v1/err".format(self.ep.settings.port),
        )
        eq_(response.code, 418)
        payload = json.loads(body)
        eq_(payload['error'], "Test Error")


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

            http = httplib.HTTPSConnection(
                "localhost:{}".format(self.ep.settings.proxy_protocol_port),
                context=SSLContextWrapper(self._create_context(None)))
            try:
                http.request('GET', '/v1/err')
                response = http.getresponse()
                return response, response.read()
            finally:
                http.close()

        response, body = yield deferToThread(proxy_request)
        eq_(response.status, 418)
        payload = json.loads(body)
        eq_(payload['error'], "Test Error")
        ok_(self.logs.logged_ci(lambda ci: ci.get('remote_ip') == ip))


class TestMemUsage(IntegrationBase):

    def endpoint_kwargs(self):
        return dict(
            super(TestMemUsage, self).endpoint_kwargs(),
            memusage_port=9040
        )

    @inlineCallbacks
    def test_memusage(self):
        port = self.ep.settings.memusage_port
        response, body = yield _agent(
            'GET',
            "http://localhost:{}/_memusage".format(port),
        )
        eq_(response.code, 200)
        ok_('rusage' in body)
        ok_('Logger' in body)
        if find_executable('pmap'):
            ok_('RSS' in body)  # pmap -x output
        if hasattr(sys, 'pypy_version_info'):  # pragma: nocover
            ok_('size: ' in body)
            ok_('rpy_unicode' in body)
            ok_('get_stats_asmmemmgr: (' in body)


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
