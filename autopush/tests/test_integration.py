import httplib
import json
import logging
import os
import random
import signal
import subprocess
import time
import urlparse
import uuid
from unittest.case import SkipTest

import boto
import ecdsa
import psutil
import websocket
import twisted.internet.base
from autobahn.twisted.websocket import WebSocketServerFactory
from jose import jws
from nose.tools import eq_, ok_
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.threads import deferToThread
from twisted.web.client import Agent
from twisted.test.proto_helpers import AccumulatingProtocol

from autopush import __version__
import autopush.db as db
from autopush.db import (
    create_rotating_message_table,
    get_month,
    has_connected_this_month
)
from autopush.settings import AutopushSettings
from autopush.utils import base64url_encode

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
    def __init__(self, url, use_webpush=False):
        self.url = url
        self.uaid = None
        self.ws = None
        self.use_webpush = use_webpush
        self.channels = {}
        self.messages = {}
        self._crypto_key = """\
keyid="http://example.org/bob/keys/123;salt="XZwpw6o37R-6qoZjw6KwAw"\
"""

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
            http = httplib.HTTPSConnection(url.netloc)
        else:
            http = httplib.HTTPConnection(url.netloc)

        http.request("DELETE", url.path)
        resp = http.getresponse()
        http.close()
        eq_(resp.status, status)

    def send_notification(self, channel=None, version=None, data=None,
                          use_header=True, status=None, ttl=200,
                          timeout=0.2, vapid=None, endpoint=None):
        if not channel:
            channel = random.choice(self.channels.keys())

        endpoint = endpoint or self.channels[channel]
        url = urlparse.urlparse(endpoint)
        http = None
        if url.scheme == "https":  # pragma: nocover
            http = httplib.HTTPSConnection(url.netloc)
        else:
            http = httplib.HTTPConnection(url.netloc)

        if self.use_webpush:
            headers = {}
            if ttl is not None:
                headers = {"TTL": str(ttl)}
            if use_header:
                headers.update({
                    "Content-Type": "application/octet-stream",
                    "Content-Encoding": "aesgcm-128",
                    "Encryption": self._crypto_key,
                    "Crypto-Key": 'keyid="a1"; key="JcqK-OLkJZlJ3sJJWstJCA"',
                })
            if vapid:
                headers.update({
                    "Authorization": "Bearer " + vapid.get('auth')
                })
                ckey = 'p256ecdsa="' + vapid.get('crypto-key') + '"'
                headers.update({
                    'Crypto-Key': headers.get('Crypto-Key') + ';' + ckey
                })
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
        location = resp.getheader("Location", None)
        log.debug("Response Headers: %s", resp.getheaders())
        if self.use_webpush:
            if status >= 200 and status < 300:
                ok_(location is not None)
            if status == 201 and ttl is not None:
                ttl_header = resp.getheader("TTL")
                eq_(ttl_header, str(ttl))
            if ttl != 0 and status == 201:
                assert(location is not None)
                if channel in self.messages:
                    self.messages[channel].append(location)
                else:
                    self.messages[channel] = [location]
        else:
            # Simple Push messages are not individually addressable.
            assert(location is None)

        # Pull the notification if connected
        if self.ws and self.ws.connected:
            return object.__getattribute__(self, "get_notification")(timeout)

    def get_notification(self, timeout=1):
        self.ws.settimeout(timeout)
        try:
            d = self.ws.recv()
            log.debug("Recv: %s", d)
            return json.loads(d)
        except:
            return None

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


class IntegrationBase(unittest.TestCase):
    track_objects = True
    track_objects_excludes = [AutopushSettings, WebSocketServerFactory]

    def setUp(self):
        import cyclone.web
        from autobahn.twisted.websocket import WebSocketServerFactory
        from autobahn.twisted.resource import WebSocketResource
        from autopush.main import skip_request_logging
        from autopush.endpoint import (
            EndpointHandler,
            MessageHandler,
            RegistrationHandler,
        )
        from autopush.settings import AutopushSettings
        from autopush.websocket import (
            PushServerProtocol,
            RouterHandler,
            NotificationHandler,
            DefaultResource,
            StatusResource,
        )
        from twisted.web.server import Site

        router_table = os.environ.get("ROUTER_TABLE", "router_int_test")
        storage_table = os.environ.get("STORAGE_TABLE", "storage_int_test")
        message_table = os.environ.get("MESSAGE_TABLE", "message_int_test")

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
            endpoint_port="9020",
            router_port="9030",
            router_tablename=router_table,
            storage_tablename=storage_table,
            message_tablename=message_table,
        )

        # Websocket server
        self._ws_url = "ws://localhost:9010/"
        factory = WebSocketServerFactory(self._ws_url)
        factory.protocol = PushServerProtocol
        factory.protocol.ap_settings = settings
        factory.setProtocolOptions(
            webStatus=False,
            openHandshakeTimeout=5,
        )
        settings.factory = factory
        resource = DefaultResource(WebSocketResource(factory))
        resource.putChild("status", StatusResource())
        self.websocket = reactor.listenTCP(9010, Site(resource))

        # Websocket HTTP router
        # Internal HTTP notification router
        r = RouterHandler
        r.ap_settings = settings
        n = NotificationHandler
        n.ap_settings = settings
        ws_site = cyclone.web.Application([
            (r"/push/([^\/]+)", r),
            (r"/notif/([^\/]+)(/([^\/]+))?", n),
        ],
            default_host=settings.router_hostname,
            log_function=skip_request_logging,
            debug=False,
        )
        self.ws_website = reactor.listenTCP(9030, ws_site)

        # Endpoint HTTP router
        site = cyclone.web.Application([
            (r"/push/(v\d+)?/?([^\/]+)", EndpointHandler,
             dict(ap_settings=settings)),
            (r"/m/([^\/]+)", MessageHandler, dict(ap_settings=settings)),
            # PUT /register/ => connect info
            # GET /register/uaid => chid + endpoint
            (r"/register(?:/(.+))?", RegistrationHandler,
             dict(ap_settings=settings)),
        ],
            default_host=settings.hostname,
            log_function=skip_request_logging,
            debug=False,
        )
        self.website = reactor.listenTCP(9020, site)
        self._settings = settings

    def _make_v0_endpoint(self, uaid, chid):
        return self._settings.endpoint_url + '/push/' + \
            self._settings.fernet.encrypt(
                (uaid + ":" + chid).encode('utf-8'))

    @inlineCallbacks
    def tearDown(self):
        dones = [self.websocket.stopListening(), self.website.stopListening(),
                 self.ws_website.stopListening()]
        for d in filter(None, dones):
            yield d

        # Dirty reactor unless we shut down the cached connections
        yield self._settings.agent._pool.closeCachedConnections()

    @inlineCallbacks
    def quick_register(self, use_webpush=False):
        client = Client("ws://localhost:9010/", use_webpush=use_webpush)
        yield client.connect()
        yield client.hello()
        yield client.register()
        returnValue(client)

    @inlineCallbacks
    def shut_down(self, client=None):
        if client:
            yield client.disconnect()


class TestSimple(IntegrationBase):
    @inlineCallbacks
    def test_delivery_while_disconnected(self):
        client = yield self.quick_register()
        yield client.disconnect()
        self.assertTrue(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        self.assertTrue(result != {})
        self.assertTrue(len(result["updates"]) == 1)
        eq_(result["updates"][0]["channelID"], chan)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_delivery_repeat_without_ack(self):
        client = yield self.quick_register()
        yield client.disconnect()
        self.assertTrue(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        self.assertTrue(result != {})
        self.assertTrue(len(result["updates"]) == 1)
        eq_(result["updates"][0]["channelID"], chan)

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        self.assertTrue(result != {})
        self.assertTrue(result["updates"] > 0)
        eq_(result["updates"][0]["channelID"], chan)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_direct_delivery_without_ack(self):
        client = yield self.quick_register()
        result = yield client.send_notification()
        ok_(result != {})
        yield client.disconnect()
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
        self.assertTrue(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        update = result["updates"][0]
        eq_(update["channelID"], chan)
        yield client.ack(chan, update["version"])
        yield client.disconnect()
        time.sleep(0.2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_no_delivery_to_unregistered(self):
        client = yield self.quick_register()
        yield client.disconnect()
        self.assertTrue(client.channels)
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
        c = yield deferToThread(self._settings.router.get_uaid, client.uaid)
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
            c = yield deferToThread(self._settings.router.get_uaid,
                                    client.uaid)
            if has_connected_this_month(c):
                break
            else:  # pragma: nocover
                times += 1
                yield client.sleep(1)
        log.debug("Last connected time: %s", c.get("last_connect", "None"))
        eq_(True, has_connected_this_month(c))


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
        self.assertTrue(client.channels)
        chan = client.channels.keys()[0]

        # Invalid UTF-8 byte sequence.
        data = b"\xc3\x28\xa0\xa1\xe2\x28\xa1"
        result = yield client.send_notification(data=data)

        ok_(result is not None)
        eq_(result["messageType"], "notification")
        eq_(result["channelID"], chan)
        eq_(result["data"], "wyigoeIooQ")

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
    @inlineCallbacks
    def test_hello_only_has_two_calls(self):
        db.TRACK_DB_CALLS = True
        client = Client(self._ws_url, use_webpush=True)
        yield client.connect()
        result = yield client.hello()
        ok_(result != {})
        eq_(result["use_webpush"], True)
        yield client.wait_for(lambda: len(db.DB_CALLS) == 2)
        eq_(db.DB_CALLS, ['register_user', 'fetch_messages'])
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

    @inlineCallbacks
    def test_basic_delivery_v0_endpoint(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        endpoint = self._make_v0_endpoint(
            client.uaid, client.channels.keys()[0])
        result = yield client.send_notification(endpoint=endpoint, data=data)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
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
        client = yield self.quick_register(use_webpush=True)
        ok_(client.channels)
        chan = client.channels.keys()[0]

        result = yield client.send_notification(data=data)
        eq_(result["channelID"], chan)
        eq_(result["data"], base64url_encode(data))
        yield client.ack(result["channelID"], result["version"])

        yield client.unregister(chan)
        result = yield client.send_notification(data=data, status=404)
        eq_(result, None)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_no_delivery_to_unregistered_on_reconnect(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(data=data)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result["channelID"], chan)
        eq_(result["data"], base64url_encode(data))

        yield client.unregister(chan)
        yield client.disconnect()
        time.sleep(1)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
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
        assert(result is not None)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], base64url_encode(data))
        eq_(result["messageType"], "notification")
        yield self.shut_down(client)

    @inlineCallbacks
    def test_ttl_not_present_connected_no_ack(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, ttl=None)
        assert(result is not None)
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
        assert(result is not None)
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
    def test_message_without_crypto_headers(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, use_header=False,
                                                status=400)
        eq_(result, None)
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
        self.assertTrue(client.channels)
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
            prefix=self._settings._message_prefix, delta=-1)
        lm_message = self._settings.message_tables[last_month]
        yield deferToThread(
            self._settings.router.update_message_month,
            client.uaid,
            last_month
        )

        # Verify the move
        c = yield deferToThread(self._settings.router.get_uaid, client.uaid)
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
            self._settings.message.all_channels, client.uaid
        )
        eq_(exists, True)
        eq_(len(chans), 1)
        yield deferToThread(
            lm_message.save_channels,
            client.uaid,
            chans
        )

        # Remove the channels entry entirely from this month
        yield deferToThread(self._settings.message.table.delete_item,
                            uaid=client.uaid,
                            chidmessageid=" "
                            )

        # Verify the channel is gone
        exists, chans = yield deferToThread(
            self._settings.message.all_channels,
            client.uaid
        )
        eq_(exists, False)
        eq_(len(chans), 0)

        # Send in a notification, verify it landed in last months notification
        # table
        data = uuid.uuid4().hex
        yield client.send_notification(data=data)
        notifs = yield deferToThread(lm_message.fetch_messages, client.uaid)
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
        server_client = self._settings.clients[client.uaid]
        eq_(server_client.ps.rotate_message_table, True)

        # Acknowledge the notification, which triggers the migration
        yield client.ack(chan, result["version"])

        # Wait up to 2 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 2:
            c = yield deferToThread(self._settings.router.get_uaid,
                                    client.uaid)
            if c["current_month"] == self._settings.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(self._settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], self._settings.current_msg_month)
        eq_(server_client.ps.rotate_message_table, False)

        # Verify the client moved last_connect
        eq_(True, has_connected_this_month(c))

        # Verify the channels were moved
        exists, chans = yield deferToThread(
            self._settings.message.all_channels,
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
            prefix=self._settings._message_prefix, delta=-1)
        lm_message = self._settings.message_tables[last_month]
        yield deferToThread(
            self._settings.router.update_message_month,
            client.uaid,
            last_month
        )

        # Verify the move
        c = yield deferToThread(self._settings.router.get_uaid, client.uaid)
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
            self._settings.message.all_channels, client.uaid
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
        yield client.send_notification(data=data)
        notifs = yield deferToThread(lm_message.fetch_messages, client.uaid)
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
        server_client = self._settings.clients[client.uaid]
        eq_(server_client.ps.rotate_message_table, True)

        # Acknowledge the notification, which triggers the migration
        yield client.ack(chan, result["version"])

        # Wait up to 2 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 2:
            c = yield deferToThread(self._settings.router.get_uaid,
                                    client.uaid)
            if c["current_month"] == self._settings.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(self._settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], self._settings.current_msg_month)
        eq_(server_client.ps.rotate_message_table, False)

        # Verify the client moved last_connect
        eq_(True, has_connected_this_month(c))

        # Verify the channels were moved
        exists, chans = yield deferToThread(
            self._settings.message.all_channels,
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
            prefix=self._settings._message_prefix, delta=-1)
        yield deferToThread(
            self._settings.router.update_message_month,
            client.uaid,
            last_month
        )

        # Verify the move
        c = yield deferToThread(self._settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], last_month)

        # Verify there's no channels
        exists, chans = yield deferToThread(
            self._settings.message.all_channels,
            client.uaid
        )
        eq_(exists, False)
        eq_(len(chans), 0)

        # Connect the client, verify the migration
        yield client.connect()
        yield client.hello()

        # Check that the client is going to rotate the month
        server_client = self._settings.clients[client.uaid]
        eq_(server_client.ps.rotate_message_table, True)

        # Wait up to 2 seconds for the table rotation to occur
        start = time.time()
        while time.time()-start < 2:
            c = yield deferToThread(self._settings.router.get_uaid,
                                    client.uaid)
            if c["current_month"] == self._settings.current_msg_month:
                break
            else:
                yield deferToThread(time.sleep, 0.2)

        # Verify the month update in the router table
        c = yield deferToThread(self._settings.router.get_uaid, client.uaid)
        eq_(c["current_month"], self._settings.current_msg_month)
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
        # check that the client actually registered the key.

        # Send an update with a properly formatted key.
        yield client.send_notification(vapid=vapid)

        # now try an invalid key.
        new_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        vapid = _get_vapid(new_key, claims)

        yield client.send_notification(
            vapid=vapid,
            status=400)

        yield self.shut_down(client)


class TestHealth(IntegrationBase):
    @inlineCallbacks
    def test_status(self):
        agent = Agent(reactor)
        response = yield agent.request(
            "GET",
            b"http://localhost:9010/status"
        )

        proto = AccumulatingProtocol()
        proto.closedDeferred = Deferred()
        response.deliverBody(proto)
        yield proto.closedDeferred

        payload = json.loads(proto.data)
        eq_(payload, {"status": "OK", "version": __version__})
