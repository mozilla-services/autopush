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
import psutil
import websocket
from nose.tools import eq_, ok_
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads import deferToThread

log = logging.getLogger(__name__)
here_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.dirname(os.path.dirname(here_dir))
moto_process = None

import twisted.internet.base
twisted.internet.base.DelayedCall.debug = True


def setUp():
    boto_path = os.path.join(root_dir, "automock", "boto.cfg")
    boto.config.load_from_path(boto_path)
    if "SKIP_INTEGRATION" in os.environ:  # pragma: nocover
        raise SkipTest("Skipping integration tests")
    global moto_process
    cmd = "moto_server dynamodb2 -p 5000"
    moto_process = subprocess.Popen(cmd, shell=True, env=os.environ)


def tearDown():
    global moto_process
    # This kinda sucks, but its the only way to nuke the child procs
    proc = psutil.Process(pid=moto_process.pid)
    child_procs = proc.children(recursive=True)
    for p in [proc] + child_procs:
        os.kill(p.pid, signal.SIGTERM)
    moto_process.wait()

    # Clear out the boto config that was loaded so the rest of the tests run
    # fine
    for section in boto.config.sections():
        boto.config.remove_section(section)


class Client(object):
    """Test Client"""
    def __init__(self, url, use_webpush=False):
        self.url = url
        self.uaid = None
        self.ws = None
        self.use_webpush = use_webpush
        self.channels = {}
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

    def hello(self):
        if self.channels:
            chans = self.channels.keys()
        else:
            chans = []
        hello_dict = dict(messageType="hello", uaid=self.uaid or "",
                          channelIDs=chans)
        if self.use_webpush:
            hello_dict["use_webpush"] = True
        msg = json.dumps(hello_dict)
        log.debug("Send: %s", msg)
        self.ws.send(msg)
        result = json.loads(self.ws.recv())
        log.debug("Recv: %s", result)
        if self.uaid and self.uaid != result["uaid"]:  # pragme: nocover
            log.debug("Mismatch on re-using uaid. Old: %s, New: %s",
                      self.uaid, result["uaid"])
            self.channels = {}
        self.uaid = result["uaid"]
        eq_(result["status"], 200)
        return result

    def register(self, chid=None):
        chid = chid or str(uuid.uuid4())
        msg = json.dumps(dict(messageType="register", channelID=chid))
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

    def send_notification(self, channel=None, version=None, data=None,
                          use_header=True, status=200, ttl=200):
        if not channel:
            channel = random.choice(self.channels.keys())

        endpoint = self.channels[channel]
        url = urlparse.urlparse(endpoint)
        http = None
        if url.scheme == "https":
            http = httplib.HTTPSConnection(url.netloc)
        else:
            http = httplib.HTTPConnection(url.netloc)

        if self.use_webpush:
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Encoding": "aesgcm-128",
                "Encryption": self._crypto_key,
                "Encryption-Key": 'keyid="a1"; key="JcqK-OLkJZlJ3sJJWstJCA"',
                "TTL": str(ttl),
            }
            body = data or ""
            method = "POST"
            status = 201
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

        log.debug("%s body: %s", method, body)
        http.request(method, url.path, body, headers)
        resp = http.getresponse()
        log.debug("%s Response: %s", method, resp.read())
        eq_(resp.status, status)
        if self.use_webpush and ttl != 0:
            assert(resp.getheader("Location", None) is not None)

        # Pull the notification if connected
        if self.ws and self.ws.connected:
            result = json.loads(self.ws.recv())
            return result

    def get_notification(self, timeout=0.2):
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
        self.ws.send_close()
        self.ws.close()
        self.ws = None


class IntegrationBase(unittest.TestCase):
    def setUp(self):
        import cyclone.web
        from autobahn.twisted.websocket import WebSocketServerFactory
        from autopush.main import skip_request_logging
        from autopush.endpoint import (EndpointHandler, RegistrationHandler)
        from autopush.settings import AutopushSettings
        from autopush.websocket import (
            SimplePushServerProtocol,
            RouterHandler,
            NotificationHandler,
        )
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
            endpoint_port="9020",
            router_port="9030"
        )

        # Websocket server
        self._ws_url = "ws://localhost:9010/"
        factory = WebSocketServerFactory(self._ws_url)
        factory.protocol = SimplePushServerProtocol
        factory.protocol.ap_settings = settings
        factory.setProtocolOptions(
            webStatus=False,
            maxFramePayloadSize=2048,
            maxMessagePayloadSize=2048,
            openHandshakeTimeout=5,
        )
        settings.factory = factory
        self.websocket = reactor.listenTCP(9010, factory)

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
            log_function=skip_request_logging
        )
        self.ws_website = reactor.listenTCP(9030, ws_site)

        # Endpoint HTTP router
        site = cyclone.web.Application([
            (r"/push/([^\/]+)", EndpointHandler, dict(ap_settings=settings)),
            # PUT /register/ => connect info
            # GET /register/uaid => chid + endpoint
            (r"/register(?:/(.+))?", RegistrationHandler,
             dict(ap_settings=settings)),
        ],
            default_host=settings.hostname,
            log_function=skip_request_logging
        )
        self.website = reactor.listenTCP(9020, site)
        self._settings = settings

    def tearDown(self):
        self.websocket.stopListening()
        self.website.stopListening()
        self.ws_website.stopListening()

        # Dirty reactor unless we shut down the cached connections
        return self._settings.agent._pool.closeCachedConnections()

    @inlineCallbacks
    def quick_register(self, use_webpush=False):
        client = Client("ws://localhost:9010/", use_webpush=use_webpush)
        yield client.connect()
        yield client.hello()
        yield client.register()
        returnValue(client)


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
        self.assertEquals(result["updates"][0]["channelID"], chan)
        yield client.disconnect()

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
        self.assertEquals(result["updates"][0]["channelID"], chan)

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        self.assertTrue(result != {})
        self.assertTrue(result["updates"] > 0)
        self.assertEquals(result["updates"][0]["channelID"], chan)
        yield client.disconnect()

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
        self.assertEquals(update["channelID"], chan)
        yield client.ack(chan, update["version"])
        yield client.disconnect()
        time.sleep(0.2)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield client.disconnect()

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
        self.assertEquals(update["channelID"], chan)

        yield client.unregister(chan)
        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield client.disconnect()

    @inlineCallbacks
    def test_deliver_version(self):
        client = yield self.quick_register()
        result = yield client.send_notification(version=12)
        ok_(result is not None)
        eq_(result["updates"][0]["version"], 12)
        yield client.disconnect()

    @inlineCallbacks
    def test_deliver_version_without_header(self):
        client = yield self.quick_register()
        result = yield client.send_notification(version=12, use_header=False)
        ok_(result is not None)
        eq_(result["updates"][0]["version"], 12)
        yield client.disconnect()


class TestData(IntegrationBase):
    @inlineCallbacks
    def test_data_delivery(self):
        client = yield self.quick_register()
        result = yield client.send_notification(data="howdythere")
        ok_(result is not None)
        eq_(result["updates"][0]["data"], "howdythere")
        yield client.disconnect()

    @inlineCallbacks
    def test_data_delivery_without_header(self):
        client = yield self.quick_register()
        result = yield client.send_notification(data="howdythere",
                                                use_header=False)
        ok_(result is not None)
        eq_(result["updates"][0]["data"], "howdythere")
        yield client.disconnect()


class TestLoop(IntegrationBase):
    @inlineCallbacks
    def test_basic_deliver(self):
        client = yield self.quick_register()
        result = yield client.send_notification()
        ok_(result != {})
        yield client.disconnect()

    @inlineCallbacks
    def test_can_ping(self):
        client = yield self.quick_register()
        yield client.ping()
        yield client.disconnect()

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
        yield client.disconnect()


class TestWebPush(IntegrationBase):
    @inlineCallbacks
    def test_hello_echo(self):
        client = Client(self._ws_url, use_webpush=True)
        yield client.connect()
        result = yield client.hello()
        ok_(result != {})
        eq_(result["use_webpush"], True)
        yield client.disconnect()

    @inlineCallbacks
    def test_basic_delivery(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], data)
        eq_(result["messageType"], "notification")
        yield client.disconnect()

    @inlineCallbacks
    def test_delivery_repeat_without_ack(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data, status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(result["data"], data)

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(result["data"], data)
        yield client.disconnect()

    @inlineCallbacks
    def test_multiple_delivery_repeat_without_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data, status=202)
        yield client.send_notification(data=data2, status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])
        yield client.disconnect()

    @inlineCallbacks
    def test_multiple_delivery_with_single_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data, status=202)
        yield client.send_notification(data=data2, status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])
        ok_(result["messageType"], "notification")
        result = yield client.get_notification()
        eq_(result, None)
        yield client.disconnect()

    @inlineCallbacks
    def test_multiple_delivery_with_multiple_ack(self):
        data = str(uuid.uuid4())
        data2 = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        yield client.send_notification(data=data, status=202)
        yield client.send_notification(data=data2, status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in [data, data2])
        result2 = yield client.get_notification()
        ok_(result2 != {})
        ok_(result2["data"] in [data, data2])
        yield client.ack(result2["channelID"], result2["version"])
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield client.disconnect()

    @inlineCallbacks
    def test_no_delivery_to_unregistered(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(data=data, status=202)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result["channelID"], chan)
        eq_(result["data"], data)

        yield client.unregister(chan)
        yield client.disconnect()
        time.sleep(1)
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        eq_(result, None)
        yield client.disconnect()

    @inlineCallbacks
    def test_ttl_0_connected(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data, ttl=0)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], data)
        eq_(result["messageType"], "notification")
        yield client.disconnect()

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
        yield client.disconnect()

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
        yield client.disconnect()
