import json
import uuid

import twisted.internet.base
from cryptography.fernet import Fernet, InvalidToken
from mock import Mock, patch
from nose.tools import eq_, ok_
from twisted.internet.defer import inlineCallbacks
from twisted.trial import unittest


import autopush.utils as utils
from autopush.db import (
    ProvisionedThroughputExceededException,
    Message,
    ItemNotFound,
    create_rotating_message_table,
    has_connected_this_month,
)
from autopush.exceptions import RouterException
from autopush.http import EndpointHTTPFactory
from autopush.metrics import SinkMetrics
from autopush.router import routers_from_settings
from autopush.router.interface import IRouter
from autopush.settings import AutopushSettings
from autopush.tests.client import Client
from autopush.tests.test_db import make_webpush_notification
from autopush.tests.support import test_db
from autopush.utils import (
    generate_hash,
)
from autopush.web.message import MessageHandler
from autopush.web.registration import NewRegistrationHandler

dummy_uaid = uuid.UUID("abad1dea00000000aabbccdd00000000")
dummy_chid = uuid.UUID("deadbeef00000000decafbad00000000")
dummy_token = dummy_uaid.hex + ":" + str(dummy_chid)


def setUp():
    from .test_integration import setUp
    setUp()
    create_rotating_message_table()


def tearDown():
    from .test_integration import tearDown
    tearDown()


class FileConsumer(object):  # pragma: no cover
    def __init__(self, fileObj):
        self.file = fileObj

    def write(self, data):
        self.file.write(data)


class MessageTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
            crypto_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        )
        db = test_db()
        self.message_mock = db.message = Mock(spec=Message)
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)

        app = EndpointHTTPFactory.for_handler(MessageHandler, settings, db=db)
        self.client = Client(app)

    def url(self, **kwargs):
        return '/m/{message_id}'.format(**kwargs)

    @inlineCallbacks
    def test_delete_token_invalid(self):
        self.fernet_mock.configure_mock(**{
            "decrypt.side_effect": InvalidToken})
        resp = yield self.client.delete(self.url(message_id='%20'))
        eq_(resp.get_status(), 400)

    @inlineCallbacks
    def test_delete_token_wrong_components(self):
        self.fernet_mock.decrypt.return_value = "123:456"
        resp = yield self.client.delete(self.url(message_id="ignored"))
        eq_(resp.get_status(), 400)

    @inlineCallbacks
    def test_delete_token_wrong_kind(self):
        tok = ":".join(["r", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        resp = yield self.client.delete(self.url(message_id='ignored'))
        eq_(resp.get_status(), 400)

    @inlineCallbacks
    def test_delete_invalid_timestamp_token(self):
        tok = ":".join(["02", str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        resp = yield self.client.delete(self.url(message_id='ignored'))
        eq_(resp.get_status(), 400)

    @inlineCallbacks
    def test_delete_success(self):
        tok = ":".join(["m", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})
        resp = yield self.client.delete(self.url(message_id="123-456"))
        self.message_mock.delete_message.assert_called()
        eq_(resp.get_status(), 204)

    @inlineCallbacks
    def test_delete_topic_success(self):
        tok = ":".join(["01", dummy_uaid.hex, str(dummy_chid), "Inbox"])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})
        resp = yield self.client.delete(self.url(message_id="123-456"))
        self.message_mock.delete_message.assert_called()
        eq_(resp.get_status(), 204)

    @inlineCallbacks
    def test_delete_topic_error_parts(self):
        tok = ":".join(["01", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})
        resp = yield self.client.delete(self.url(message_id="123-456"))
        eq_(resp.get_status(), 400)

    @inlineCallbacks
    def test_delete_db_error(self):
        tok = ":".join(["m", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.side_effect":
            ProvisionedThroughputExceededException(None, None)})
        resp = yield self.client.delete(self.url(message_id="ignored"))
        eq_(resp.get_status(), 503)


class RegistrationTestCase(unittest.TestCase):
    CORS_HEAD = "POST"

    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
            bear_hash_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=',
        )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)

        self.db = db = test_db()
        db.router.register_user.return_value = (True, {}, {})
        db.router.get_uaid.return_value = {
            "router_type": "test",
            "router_data": dict()
        }
        db.create_initial_message_tables()

        self.routers = routers = routers_from_settings(settings, db, Mock())
        routers["test"] = Mock(spec=IRouter)
        app = EndpointHTTPFactory(settings, db=db, routers=routers)
        self.client = Client(app)

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.reg = NewRegistrationHandler(app, self.request_mock)
        self.auth = ("WebPush %s" %
                     generate_hash(settings.bear_hash_key[0], dummy_uaid.hex))

        self.settings = settings

    def url(self, router_token='test', **kwargs):
        urlfmt = '/v1/{router_type}/{router_token}/registration'
        result = urlfmt.format(router_token=router_token, **kwargs)
        if kwargs.get('uaid'):
            result += '/' + kwargs.get('uaid')
            if kwargs.get('chid'):
                result += '/subscription/' + kwargs.get('chid')
        return result

    def patch(self, *args, **kwargs):
        """Patch an object only for the duration of a test"""
        patch_obj = patch(*args, **kwargs)
        patch_obj.__enter__()
        self.addCleanup(patch_obj.__exit__)

    def test_base_tags(self):
        self.reg._base_tags = []
        self.reg.request = Mock(headers={'user-agent': 'test'},
                                host='example.com:8080')
        tags = self.reg.base_tags()
        eq_(tags, ['user_agent:test', 'host:example.com:8080'])
        # previously failed
        tags = self.reg.base_tags()
        eq_(tags, ['user_agent:test', 'host:example.com:8080'])

    def _check_error(self, resp, code, errno, error, message=None):
        d = json.loads(resp.content)
        eq_(d.get("code"), code)
        eq_(d.get("errno"), errno)
        eq_(d.get("error"), error)

    def test_init_info(self):
        h = self.request_mock.headers
        h["user-agent"] = "myself"
        d = self.reg._init_info()
        eq_(d["user_agent"], "myself")
        self.request_mock.remote_ip = "local1"
        d = self.reg._init_info()
        eq_(d["remote_ip"], "local1")
        self.request_mock.headers["x-forwarded-for"] = "local2"
        d = self.reg._init_info()
        eq_(d["remote_ip"], "local2")

    def test_settings_crypto_key(self):
        fake = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        settings = AutopushSettings(crypto_key=fake)
        eq_(settings.fernet._fernets[0]._encryption_key,
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

        fake2 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='
        settings = AutopushSettings(crypto_key=[fake, fake2])
        eq_(settings.fernet._fernets[0]._encryption_key,
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        eq_(settings.fernet._fernets[1]._encryption_key,
            '\x10A\x04\x10A\x04\x10A\x04\x10A\x04\x10A\x04\x10')

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = False
        ok_(reg._headers.get(ch1) != "*")
        ok_(reg._headers.get(ch2) != self.CORS_HEAD)

        reg.clear_header(ch1)
        reg.clear_header(ch2)
        reg.ap_settings.cors = True
        reg.prepare()
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], self.CORS_HEAD)

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.prepare()
        reg.head(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], self.CORS_HEAD)

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.prepare()
        reg.options(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], self.CORS_HEAD)

    @inlineCallbacks
    def test_post(self):
        self.patch('uuid.uuid4', return_value=dummy_uaid)

        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        resp = yield self.client.post(
            self.url(router_type='simplepush', router_token='yyy'),
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                type="simplepush",
                channelID=str(dummy_chid),
                data={},
            ))
        )
        eq_(resp.get_status(), 200)

        payload = json.loads(resp.content)
        eq_(payload["uaid"], dummy_uaid.hex)
        eq_(payload["channelID"], dummy_chid.hex)
        eq_(payload["endpoint"], "http://localhost/wpush/v1/abcd123")
        ok_("secret" in payload)

    @inlineCallbacks
    def test_post_gcm(self):
        self.patch('uuid.uuid4',
                   side_effect=(uuid.uuid4(), dummy_uaid, dummy_chid))

        from autopush.router.gcm import GCMRouter
        sids = {"182931248179192": {"auth": "aailsjfilajdflijdsilfjsliaj"}}
        gcm = GCMRouter(
            self.settings,
            {"dryrun": True, "senderIDs": sids},
            SinkMetrics()
        )
        self.routers["gcm"] = gcm
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        resp = yield self.client.post(
            self.url(router_type="gcm", router_token="182931248179192"),
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                channelID=str(dummy_chid),
                token="182931248179192",
            ))
        )
        eq_(resp.get_status(), 200)

        payload = json.loads(resp.content)
        eq_(payload["uaid"], dummy_uaid.hex)
        eq_(payload["channelID"], dummy_chid.hex)
        eq_(payload["endpoint"], "http://localhost/wpush/v1/abcd123")
        calls = self.db.router.register_user.call_args
        call_args = calls[0][0]
        eq_(True, has_connected_this_month(call_args))
        ok_("secret" in payload)

    @inlineCallbacks
    def test_post_invalid_args(self, *args):
        resp = yield self.client.post(
            self.url(router_type="foo"),
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                type="invalid",
                data={},
            ))
        )
        self._check_error(resp, 400, 108, "Bad Request")

    @inlineCallbacks
    def test_post_bad_router_type(self):
        self.patch('uuid.uuid4', return_value=dummy_uaid)

        resp = yield self.client.post(
            self.url(router_type="foo"),
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                type="invalid",
                channelID=str(dummy_chid),
                data={},
            ))
        )
        self._check_error(resp, 400, 108, "Bad Request")

    @inlineCallbacks
    def test_post_bad_router_register(self, *args):
        router = self.routers["simplepush"]
        rexc = RouterException("invalid", status_code=402, errno=107)
        router.register = Mock(side_effect=rexc)

        resp = yield self.client.post(
            self.url(router_type="simplepush"),
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                type="simplepush",
                channelID=str(dummy_chid),
                data={},
            ))
        )
        self._check_error(resp, rexc.status_code, rexc.errno, "")

    @inlineCallbacks
    def test_post_existing_uaid(self):
        self.patch('uuid.uuid4', return_value=dummy_chid)

        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        resp = yield self.client.post(
            self.url(router_type="test", uaid=dummy_uaid.hex) +
            "/subscription",
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                channelID=str(dummy_chid),
            ))
        )
        payload = json.loads(resp.content)
        eq_(payload["channelID"], dummy_chid.hex)
        eq_(payload["endpoint"], "http://localhost/wpush/v1/abcd123")

    @inlineCallbacks
    def test_no_uaid(self):
        self.db.router.get_uaid.side_effect = ItemNotFound
        resp = yield self.client.delete(
            self.url(router_type="webpush",
                     uaid=dummy_uaid.hex,
                     chid=str(dummy_chid))
        )
        self._check_error(resp, 410, 103, "")

    @inlineCallbacks
    def test_no_auth(self):
        resp = yield self.client.delete(
            self.url(router_type="webpush",
                     uaid=dummy_uaid.hex,
                     chid=str(dummy_chid)),
        )
        self._check_error(resp, 401, 109, "Unauthorized")

    @inlineCallbacks
    def test_bad_body(self):
        url = self.url(router_type="webpush", uaid=dummy_uaid.hex)
        resp = yield self.client.put(url, body="{invalid")
        self._check_error(resp, 400, 108, "Bad Request")

    @inlineCallbacks
    def test_post_bad_params(self):
        self.patch('uuid.uuid4', return_value=dummy_uaid)

        resp = yield self.client.delete(
            self.url(router_type="simplepush",
                     uaid=dummy_uaid.hex,
                     chid=str(dummy_chid)),
            headers={"Authorization": "WebPush Invalid"},
            body=json.dumps(dict(
                channelID=str(dummy_chid),
            ))
        )
        self._check_error(resp, 401, 109, 'Unauthorized')

    @inlineCallbacks
    def test_post_nochid(self, *args):
        self.patch('uuid.uuid4', return_value=dummy_chid)

        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        resp = yield self.client.post(
            self.url(router_type="simplepush", uaid=dummy_uaid.hex) +
            "/subscription",
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                type="simplepush",
                data={},
            ))
        )
        payload = json.loads(resp.content)
        eq_(payload["channelID"], dummy_chid.hex)
        eq_(payload["endpoint"], "http://localhost/wpush/v1/abcd123")

    @inlineCallbacks
    def test_post_with_app_server_key(self, *args):
        self.patch('uuid.uuid4', return_value=dummy_chid)

        dummy_key = "RandomKeyString"

        def mock_encrypt(cleartext):
            eq_(len(cleartext), 64)
            # dummy_uaid
            eq_(cleartext[0:16],
                'abad1dea00000000aabbccdd00000000'.decode('hex'))
            # dummy_chid
            eq_(cleartext[16:32],
                'deadbeef00000000decafbad00000000'.decode('hex'))
            # sha256(dummy_key).digest()
            eq_(cleartext[32:],
                ('47aedd050b9e19171f0fa7b8b65ca670'
                 '28f0bc92cd3f2cd3682b1200ec759007').decode('hex'))
            return 'abcd123'
        self.fernet_mock.configure_mock(**{
            'encrypt.side_effect': mock_encrypt,
        })

        resp = yield self.client.post(
            self.url(router_type="simplepush", uaid=dummy_uaid.hex) +
            "/subscription",
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                type="simplepush",
                key=utils.base64url_encode(dummy_key),
                data={},
            ))
        )
        payload = json.loads(resp.content)
        eq_(payload["channelID"], dummy_chid.hex)
        eq_(payload["endpoint"], "http://localhost/wpush/v2/abcd123")

    @inlineCallbacks
    def test_put(self, *args):
        self.patch('uuid.uuid4', return_value=dummy_uaid)

        data = dict(token="some_token")
        frouter = self.routers["test"]
        frouter.register = Mock()
        frouter.register.return_value = data

        uri = self.url(router_type='test', uaid=dummy_uaid.hex)
        resp = yield self.client.put(
            uri,
            headers={"Authorization": self.auth},
            body=json.dumps(data),
        )
        payload = json.loads(resp.content)
        eq_(payload, {})
        frouter.register.assert_called_with(
            uaid="",
            router_data=data,
            app_id='test',
        )
        user_data = self.db.router.register_user.call_args[0][0]
        eq_(user_data['uaid'], dummy_uaid.hex)
        eq_(user_data['router_type'], 'test')
        eq_(user_data['router_data']['token'], 'some_token')

    @inlineCallbacks
    def test_put_bad_auth(self, *args):
        self.patch('uuid.uuid4', return_value=dummy_uaid)

        resp = yield self.client.put(
            self.url(router_type="test", uaid=dummy_uaid.hex),
            headers={"Authorization": "Fred Smith"},
            body=json.dumps(dict(token="blah"))
        )
        self._check_error(resp, 401, 109, "Unauthorized")

    @inlineCallbacks
    def test_put_bad_uaid_path(self, *args):
        self.patch('uuid.uuid4', return_value=dummy_uaid)

        resp = yield self.client.put(
            self.url(router_type="test", uaid="invalid"),
            headers={"Authorization": "Fred Smith"},
            body=json.dumps(dict(token="blah"))
        )
        eq_(resp.get_status(), 404)

    @inlineCallbacks
    def test_put_bad_arguments(self, *args):
        self.patch('uuid.uuid4', return_value=dummy_chid)

        resp = yield self.client.put(
            self.url(router_type='foo', uaid=dummy_uaid.hex),
            headers={"Authorization": self.auth},
            body=json.dumps(dict(
                type="test",
                data=dict(token="some_token"),
            ))
        )
        self._check_error(resp, 400, 108, "Bad Request")

    @inlineCallbacks
    def test_put_bad_router_register(self):
        frouter = self.routers["test"]
        rexc = RouterException("invalid", status_code=402, errno=107)
        frouter.register = Mock(side_effect=rexc)

        resp = yield self.client.put(
            self.url(router_type='test', uaid=dummy_uaid.hex),
            headers={"Authorization": self.auth},
            body=json.dumps(dict(token="blah"))
        )
        self._check_error(resp, rexc.status_code, rexc.errno, "")

    @inlineCallbacks
    def test_delete_bad_chid_value(self):
        notif = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        messages = self.db.message
        messages.register_channel(dummy_uaid.hex, str(dummy_chid))
        messages.store_message(notif)

        resp = yield self.client.delete(
            self.url(router_type="test",
                     router_token="test",
                     uaid=dummy_uaid.hex,
                     chid=uuid.uuid4().hex),
            headers={"Authorization": self.auth},
        )
        self._check_error(resp, 410, 106, "")

    @inlineCallbacks
    def test_delete_no_such_chid(self):
        notif = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        messages = self.db.message
        messages.register_channel(dummy_uaid.hex, str(dummy_chid))
        messages.store_message(notif)

        # Moto can't handle set operations of this nature so we have
        # to mock the reply
        self.patch('autopush.db.Message.unregister_channel',
                   return_value=False)

        resp = yield self.client.delete(
            self.url(router_type="test",
                     router_token="test",
                     uaid=dummy_uaid.hex,
                     chid=str(uuid.uuid4())),
            headers={"Authorization": self.auth}
        )
        self._check_error(resp, 410, 106, "")

    @inlineCallbacks
    def test_delete_uaid(self):
        notif = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        notif2 = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        messages = self.db.message
        messages.store_message(notif)
        messages.store_message(notif2)
        self.db.router.drop_user.return_value = True

        yield self.client.delete(
            self.url(router_type="simplepush",
                     router_token="test",
                     uaid=dummy_uaid.hex),
            headers={"Authorization": self.auth},
        )
        # Note: Router is mocked, so the UAID is never actually
        # dropped.
        ok_(self.db.router.drop_user.called)
        eq_(self.db.router.drop_user.call_args_list[0][0], (dummy_uaid.hex,))

    @inlineCallbacks
    def test_delete_bad_uaid(self):
        # Return a 401 as the random UUID was never registered
        resp = yield self.client.delete(
            self.url(router_type="test", router_token="test",
                     uaid=uuid.uuid4().hex),
            headers={"Authorization": self.auth},
        )
        eq_(resp.get_status(), 401)

    @inlineCallbacks
    def test_delete_orphans(self):
        self.db.router.drop_user.return_value = False
        resp = yield self.client.delete(
            self.url(router_type="test",
                     router_token="test",
                     uaid=dummy_uaid.hex),
            headers={"Authorization": self.auth},
        )
        eq_(resp.get_status(), 410)

    @inlineCallbacks
    def test_delete_bad_auth(self, *args):
        resp = yield self.client.delete(
            self.url(router_type="test",
                     router_token="test",
                     uaid=dummy_uaid.hex),
            headers={"Authorization": "Invalid"},
        )
        eq_(resp.get_status(), 401)

    @inlineCallbacks
    def test_delete_bad_router(self):
        resp = yield self.client.delete(
            self.url(router_type="invalid",
                     router_token="test",
                     uaid=dummy_uaid.hex),
            headers={"Authorization": self.auth},
        )
        eq_(resp.get_status(), 400)

    @inlineCallbacks
    def test_get(self):
        chids = [str(dummy_chid), str(dummy_uaid)]

        self.db.message.all_channels = Mock()
        self.db.message.all_channels.return_value = (True, chids)
        resp = yield self.client.get(
            self.url(router_type="test",
                     router_token="test",
                     uaid=dummy_uaid.hex),
            headers={"Authorization": self.auth}
        )
        self.db.message.all_channels.assert_called_with(str(dummy_uaid))
        payload = json.loads(resp.content)
        eq_(chids, payload['channelIDs'])
        eq_(dummy_uaid.hex, payload['uaid'])
