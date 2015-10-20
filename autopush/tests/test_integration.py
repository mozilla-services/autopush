import httplib
import json
import logging
import os
import random
import time
import urlparse
import uuid
from unittest.case import SkipTest

import websocket
from autobahn.twisted.websocket import WebSocketServerFactory
from nose.tools import eq_, ok_
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.threads import deferToThread
from twisted.web.client import Agent
from twisted.test.proto_helpers import AccumulatingProtocol
from autopush import __version__
from autopush.settings import AutopushSettings
from base64 import urlsafe_b64encode

log = logging.getLogger(__name__)
here_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.dirname(os.path.dirname(here_dir))

import twisted.internet.base
twisted.internet.base.DelayedCall.debug = True


def setUp():
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    if "RUN_INTEGRATION" not in os.environ:  # pragma: nocover
        raise SkipTest("Skipping integration tests")


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
        if self.uaid and self.uaid != result["uaid"]:  # pragma: nocover
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
                          timeout=0.2):
        if not channel:
            channel = random.choice(self.channels.keys())

        endpoint = self.channels[channel]
        url = urlparse.urlparse(endpoint)
        http = None
        if url.scheme == "https":  # pragma: nocover
            http = httplib.HTTPSConnection(url.netloc)
        else:
            http = httplib.HTTPConnection(url.netloc)

        if self.use_webpush:
            headers = {"TTL": str(ttl)}
            if use_header:
                headers.update({
                    "Content-Type": "application/octet-stream",
                    "Content-Encoding": "aesgcm-128",
                    "Encryption": self._crypto_key,
                    "Encryption-Key":
                        'keyid="a1"; key="JcqK-OLkJZlJ3sJJWstJCA"',
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
        if self.use_webpush:
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

    def update_notification(self, location, data=None, status=None, ttl=200):
        url = urlparse.urlparse(location)
        http = None
        if url.scheme == "https":  # pragma: nocover
            http = httplib.HTTPSConnection(url.netloc)
        else:
            http = httplib.HTTPConnection(url.netloc)

        assert self.use_webpush is True

        headers = {"TTL": str(ttl)}
        if data:
            headers.update({
                "Content-Type": "application/octet-stream",
                "Content-Encoding": "aesgcm-128",
                "Encryption": self._crypto_key,
                "Encryption-Key":
                    'keyid="a1"; key="JcqK-OLkJZlJ3sJJWstJCA"',
            })
        body = data or ""
        method = "PUT"
        status = status or 201

        log.debug("%s body: %s", method, body)
        http.request(method, url.path.encode("utf-8"), body, headers)
        resp = http.getresponse()
        log.debug("%s Response (%s): %s", method, resp.status, resp.read())
        http.close()
        eq_(resp.status, status)

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
        self.ws.close()


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

        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
            endpoint_port="9020",
            router_port="9030"
        )

        # Websocket server
        self._ws_url = "ws://localhost:9010/"
        factory = WebSocketServerFactory(self._ws_url, debug=False)
        factory.protocol = PushServerProtocol
        factory.protocol.ap_settings = settings
        factory.setProtocolOptions(
            webStatus=False,
            maxFramePayloadSize=2048,
            maxMessagePayloadSize=2048,
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
            (r"/push/([^\/]+)", EndpointHandler, dict(ap_settings=settings)),
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
        self.assertEquals(result["updates"][0]["channelID"], chan)
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
        self.assertEquals(result["updates"][0]["channelID"], chan)

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        self.assertTrue(result != {})
        self.assertTrue(result["updates"] > 0)
        self.assertEquals(result["updates"][0]["channelID"], chan)
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
        self.assertEquals(update["channelID"], chan)
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
        self.assertEquals(update["channelID"], chan)

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
        eq_(result["data"], "wyigoeIooQ==")

        yield self.shut_down(client)

    @inlineCallbacks
    def test_webpush_data_delivery_to_disconnected_client(self):
        tests = {
            "d248d4e0-0ef4-41d9-8db5-2533ad8e4041": dict(
                data=b"\xe2\x82\x28\xf0\x28\x8c\xbc", result="4oIo8CiMvA=="),

            "df2363be-4d55-49c5-a1e3-aeae9450692e": dict(
                data=b"\xf0\x90\x28\xbc\xf0\x28\x8c\x28",
                result="8JAovPAojCg="),

            "6c33e055-5762-47e5-b90c-90ad9bfe3f53": dict(
                data=b"\xc3\x28\xa0\xa1\xe2\x28\xa1", result="wyigoeIooQ=="),
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
    def test_hello_echo(self):
        client = Client(self._ws_url, use_webpush=True)
        yield client.connect()
        result = yield client.hello()
        ok_(result != {})
        eq_(result["use_webpush"], True)
        yield self.shut_down(client)

    @inlineCallbacks
    def test_basic_delivery(self):
        data = str(uuid.uuid4())
        client = yield self.quick_register(use_webpush=True)
        result = yield client.send_notification(data=data)
        eq_(result["headers"]["encryption"], client._crypto_key)
        eq_(result["data"], urlsafe_b64encode(data))
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
        eq_(result["data"], urlsafe_b64encode(data))

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        eq_(result["data"], urlsafe_b64encode(data))
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
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))
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
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))
        yield client.ack(result["channelID"], result["version"])

        yield client.disconnect()
        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result != {})
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))
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
        ok_(result["data"] in map(urlsafe_b64encode, [data, data2]))
        result2 = yield client.get_notification()
        ok_(result2 != {})
        ok_(result2["data"] in map(urlsafe_b64encode, [data, data2]))
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
        eq_(result["data"], urlsafe_b64encode(data))
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
        eq_(result["data"], urlsafe_b64encode(data))

        yield client.unregister(chan)
        yield client.disconnect()
        time.sleep(1)
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
        eq_(result["data"], urlsafe_b64encode(data))
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
    def test_message_update(self):
        data = uuid.uuid4().hex
        data2 = uuid.uuid4().hex
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(data=data)
        ok_(client.messages.get(chan, []) != [])
        location = client.messages[chan][0]
        yield client.update_notification(location=location, data=data2)

        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result is not None)
        ok_(result != {})
        eq_(result["data"], urlsafe_b64encode(data2))
        yield self.shut_down(client)

    @inlineCallbacks
    def test_message_update_remove_data(self):
        data = uuid.uuid4().hex
        client = yield self.quick_register(use_webpush=True)
        yield client.disconnect()
        ok_(client.channels)
        chan = client.channels.keys()[0]
        yield client.send_notification(data=data)
        ok_(client.messages.get(chan, []) != [])
        location = client.messages[chan][0]
        yield client.update_notification(location=location)

        yield client.connect()
        yield client.hello()
        result = yield client.get_notification()
        ok_(result is not None)
        ok_(result != {})
        ok_("data" not in result)
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
