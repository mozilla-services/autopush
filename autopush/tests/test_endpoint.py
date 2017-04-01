import json
import uuid

import twisted.internet.base
from cryptography.fernet import Fernet, InvalidToken
from cyclone.web import Application
from mock import Mock
from moto import mock_dynamodb2
from nose.tools import eq_, ok_
from twisted.internet.defer import Deferred
from twisted.trial import unittest
from txstatsd.metrics.metrics import Metrics


import autopush.utils as utils
from autopush.db import (
    ProvisionedThroughputExceededException,
    Router,
    Storage,
    Message,
    ItemNotFound,
    create_rotating_message_table,
    has_connected_this_month,
)
from autopush.exceptions import RouterException
from autopush.settings import AutopushSettings
from autopush.router.interface import IRouter
from autopush.tests.test_db import make_webpush_notification
from autopush.utils import (
    generate_hash,
)
from autopush.web.message import MessageHandler
from autopush.web.registration import RegistrationHandler

mock_dynamodb2 = mock_dynamodb2()
dummy_uaid = uuid.UUID("abad1dea00000000aabbccdd00000000")
dummy_chid = uuid.UUID("deadbeef00000000decafbad00000000")
dummy_token = dummy_uaid.hex + ":" + str(dummy_chid)


def setUp():
    mock_dynamodb2.start()
    create_rotating_message_table()


def tearDown():
    mock_dynamodb2.stop()


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
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.message_mock = settings.message = Mock(spec=Message)

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.message = MessageHandler(Application(),
                                      self.request_mock,
                                      ap_settings=settings)

        self.status_mock = self.message.set_status = Mock()
        self.write_mock = self.message.write = Mock()

        d = self.finish_deferred = Deferred()
        self.message.finish = lambda: d.callback(True)

    def _make_req(self, id=None, headers=None, body='',
                  rargs=None, *args, **kwargs):
        if headers is None:
            headers = {}
        self.request_mock.body = body
        self.request_mock.headers.update(headers)
        self.message.path_kwargs = {}
        self.message.path_args = rargs or args or []
        if id is not None:
            self.message.path_kwargs = {"message_id": id}
        return dict()

    def test_delete_token_invalid(self):
        self.fernet_mock.configure_mock(**{
            "decrypt.side_effect": InvalidToken})

        def handle_finish(result):
            self.status_mock.assert_called_with(400, reason=None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req(id=''))
        return self.finish_deferred

    def test_delete_token_wrong_components(self):
        self.fernet_mock.decrypt.return_value = "123:456"

        def handle_finish(result):
            self.status_mock.assert_called_with(400, reason=None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req("ignored"))
        return self.finish_deferred

    def test_delete_token_wrong_kind(self):
        tok = ":".join(["r", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok

        def handle_finish(result):
            self.status_mock.assert_called_with(400, reason=None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req('ignored'))
        return self.finish_deferred

    def test_delete_invalid_timestamp_token(self):
        tok = ":".join(["02", str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok

        def handle_finish(result):
            self.status_mock.assert_called_with(400, reason=None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req('ignored'))
        return self.finish_deferred

    def test_delete_success(self):
        tok = ":".join(["m", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})

        def handle_finish(result):
            self.message_mock.delete_message.assert_called()
            self.status_mock.assert_called_with(204)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req("123-456"))
        return self.finish_deferred

    def test_delete_topic_success(self):
        tok = ":".join(["01", dummy_uaid.hex, str(dummy_chid), "Inbox"])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})

        def handle_finish(result):
            self.message_mock.delete_message.assert_called()
            self.status_mock.assert_called_with(204)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req("123-456"))
        return self.finish_deferred

    def test_delete_topic_success2(self):
        tok = ":".join(["01", dummy_uaid.hex, str(dummy_chid), "Inbox"])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})

        def handle_finish(result):
            self.message_mock.delete_message.assert_called()
            self.status_mock.assert_called_with(204)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req(id=None,
                                           rargs=["123-456"]))
        return self.finish_deferred

    def test_delete_topic_error_parts(self):
        tok = ":".join(["01", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.return_value": True})

        def handle_finish(result):
            self.status_mock.assert_called_with(400, reason=None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req("123-456"))
        return self.finish_deferred

    def test_delete_db_error(self):
        tok = ":".join(["m", dummy_uaid.hex, str(dummy_chid)])
        self.fernet_mock.decrypt.return_value = tok
        self.message_mock.configure_mock(**{
            "delete_message.side_effect":
            ProvisionedThroughputExceededException(None, None)})

        def handle_finish(result):
            ok_(result)
            self.status_mock.assert_called_with(503, reason=None)
        self.finish_deferred.addCallback(handle_finish)

        self.message.delete(self._make_req("ignored"))
        return self.finish_deferred


CORS_HEAD = "GET,POST,PUT,DELETE"


class RegistrationTestCase(unittest.TestCase):

    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        settings = AutopushSettings(
            hostname="localhost",
            statsd_host=None,
            bear_hash_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=',
        )
        self.fernet_mock = settings.fernet = Mock(spec=Fernet)
        self.metrics_mock = settings.metrics = Mock(spec=Metrics)
        self.router_mock = settings.router = Mock(spec=Router)
        self.storage_mock = settings.storage = Mock(spec=Storage)
        self.router_mock.register_user = Mock()
        self.router_mock.register_user.return_value = (True, {}, {})
        settings.routers["test"] = Mock(spec=IRouter)
        settings.router.get_uaid.return_value = {
            "router_type": "test",
            "router_data": dict()
        }

        self.request_mock = Mock(body=b'', arguments={}, headers={})
        self.reg = RegistrationHandler(Application(),
                                       self.request_mock,
                                       ap_settings=settings)
        self.reg.request.uri = '/v1/xxx/yyy/register'
        self.status_mock = self.reg.set_status = Mock()
        self.write_mock = self.reg.write = Mock()
        self.auth = ("WebPush %s" %
                     generate_hash(self.reg.ap_settings.bear_hash_key[0],
                                   dummy_uaid.hex))

        d = self.finish_deferred = Deferred()
        self.reg.finish = lambda: d.callback(True)
        self.settings = settings

    def _make_req(self, router_type="", router_token="", uaid=None,
                  chid=None, body="", headers=None):
        if headers is None:
            headers = {}
        self.request_mock.body = body or self.request_mock.body
        self.request_mock.headers.update(headers)
        self.reg.path_kwargs = {"router_type": router_type,
                                "router_token": router_token,
                                "uaid": uaid,
                                "chid": chid}
        return dict()

    def test_base_tags(self):
        self.reg._base_tags = []
        self.reg.request = Mock(headers={'user-agent': 'test'},
                                host='example.com:8080')
        tags = self.reg.base_tags()
        eq_(tags, ['user_agent:test', 'host:example.com:8080'])
        # previously failed
        tags = self.reg.base_tags()
        eq_(tags, ['user_agent:test', 'host:example.com:8080'])

    def _check_error(self, code, errno, error, message=None):
        d = json.loads(self.write_mock.call_args[0][0])
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

    def test_ap_settings_update(self):
        fake = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        reg = self.reg
        reg.ap_settings.update(banana="fruit")
        eq_(reg.ap_settings.banana, "fruit")
        reg.ap_settings.update(crypto_key=fake)
        eq_(reg.ap_settings.fernet._fernets[0]._encryption_key,
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_cors(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = False
        ok_(reg._headers.get(ch1) != "*")
        ok_(reg._headers.get(ch2) != CORS_HEAD)

        reg.clear_header(ch1)
        reg.clear_header(ch2)
        reg.ap_settings.cors = True
        reg.prepare()
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], CORS_HEAD)

    def test_cors_head(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.prepare()
        reg.head(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], CORS_HEAD)

    def test_cors_options(self):
        ch1 = "Access-Control-Allow-Origin"
        ch2 = "Access-Control-Allow-Methods"
        reg = self.reg
        reg.ap_settings.cors = True
        reg.prepare()
        reg.options(None)
        eq_(reg._headers[ch1], "*")
        eq_(reg._headers[ch2], CORS_HEAD)

    def test_post(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=str(dummy_chid),
            data={},
        ))
        self.reg.request.uri = "/v1/xxx/yyy/register"
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.request.headers["Authorization"] = self.auth
        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_uaid

        def handle_finish(value):
            uuid.uuid4 = old_func
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["uaid"], dummy_uaid.hex.replace('-', ''))
            eq_(call_arg["channelID"], dummy_uaid.hex)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")
            ok_("secret" in call_arg)

        self.finish_deferred.addBoth(handle_finish)
        self.reg.post(self._make_req("simplepush", "",
                                     body=self.reg.request.body))
        return self.finish_deferred

    def test_post_gcm(self, *args):
        from autopush.router.gcm import GCMRouter
        sids = {"182931248179192": {"auth": "aailsjfilajdflijdsilfjsliaj"}}
        gcm = GCMRouter(self.settings,
                        {"dryrun": True, "senderIDs": sids})
        self.reg.ap_settings.routers["gcm"] = gcm
        self.reg.request.body = json.dumps(dict(
            channelID=str(dummy_chid),
            token="182931248179192",
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["uaid"], dummy_uaid.hex)
            eq_(call_arg["channelID"], dummy_chid.hex)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")
            calls = self.reg.ap_settings.router.register_user.call_args
            call_args = calls[0][0]
            eq_(True, has_connected_this_month(call_args))
            ok_("secret" in call_arg)

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        self.finish_deferred.addCallback(handle_finish)
        self.finish_deferred.addBoth(restore)
        old_func = uuid.uuid4
        ids = [dummy_uaid, dummy_chid]
        uuid.uuid4 = lambda: ids.pop()
        self.reg.post(self._make_req("gcm", "182931248179192"))
        return self.finish_deferred

    def test_post_invalid_args(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="invalid",
            data={},
        ))

        def handle_finish(value):
            self._check_error(400, 108, "Bad Request")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req())
        return self.finish_deferred

    def test_post_bad_router_type(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="invalid",
            channelID=str(dummy_chid),
            data={},
        ))

        def handle_finish(value):
            self._check_error(400, 108, "Bad Request")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_uaid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req())
        return self.finish_deferred

    def test_post_bad_router_register(self, *args):
        frouter = Mock(spec=IRouter)
        self.reg.ap_settings.routers["simplepush"] = frouter
        rexc = RouterException("invalid", status_code=402, errno=107)
        frouter.register = Mock(side_effect=rexc)

        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=str(dummy_chid),
            data={},
        ))
        self.reg.request.uri = "/v1/xxx/yyy/register"
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self._check_error(rexc.status_code, rexc.errno, "")

        self.finish_deferred.addBoth(handle_finish)
        self.reg.post(self._make_req("simplepush", "",
                                     body=self.reg.request.body))
        return self.finish_deferred

    def test_post_existing_uaid(self, *args):
        self.reg.request.body = json.dumps(dict(
            channelID=str(dummy_chid),
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["channelID"], dummy_chid.hex)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_chid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req(router_type="test", uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_post_bad_uaid(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=str(dummy_chid),
            data={},
        ))

        def handle_finish(value):
            self._check_error(401, 109, "Unauthorized")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_uaid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req(router_type="simplepush",
                                     uaid='invalid'))
        return self.finish_deferred

    def test_no_uaid(self):
        def handle_finish(value):
            self._check_error(410, 103, "")

        self.finish_deferred.addCallback(handle_finish)
        self.settings.router.get_uaid = Mock()
        self.settings.router.get_uaid.side_effect = ItemNotFound
        self.reg.post(self._make_req(router_type="webpush",
                                     uaid=dummy_uaid.hex,
                                     chid=str(dummy_chid)))
        return self.finish_deferred

    def test_no_auth(self):
        def handle_finish(value):
            self._check_error(401, 109, "Unauthorized")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.post(self._make_req(router_type="webpush",
                                     uaid=dummy_uaid.hex,
                                     chid=str(dummy_chid)))

        return self.finish_deferred

    def test_bad_body(self):
        def handle_finish(value):
            self._check_error(401, 108, "Unauthorized")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.post(self._make_req(router_type="webpush",
                                     uaid=dummy_uaid.hex,
                                     chid=str(dummy_chid),
                                     body="{invalid"))
        return self.finish_deferred

    def test_post_bad_params(self, *args):
        self.reg.request.body = json.dumps(dict(
            channelID=str(dummy_chid),
        ))

        def handle_finish(value):
            self._check_error(401, 109, 'Unauthorized')

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_uaid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = "WebPush Invalid"
        self.reg.post(self._make_req(router_type="simplepush",
                                     uaid=dummy_uaid.hex,
                                     chid=str(dummy_chid)))
        return self.finish_deferred

    def test_post_uaid_chid(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            channelID=str(dummy_chid),
            data={},
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["channelID"], str(dummy_chid))
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_uaid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req(router_type="simplepush",
                                     uaid=dummy_uaid.hex,
                                     chid=str(dummy_chid)))
        return self.finish_deferred

    def test_post_uaid_critical_failure(self, *args):
        self.reg.request.body = json.dumps(dict(
            type="webpush",
            channelID=str(dummy_chid),
            data={},
        ))
        self.settings.router.get_uaid = Mock()
        self.settings.router.get_uaid.return_value = {
            "critical_failure": "Client is unreachable due to a configuration "
                                "error."
        }
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })

        def handle_finish(value):
            self._check_error(410, 105, "")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req(router_type="simplepush",
                                     uaid=dummy_uaid.hex,
                                     chid=str(dummy_chid)))
        return self.finish_deferred

    def test_post_nochid(self):
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            data={},
        ))
        self.fernet_mock.configure_mock(**{
            'encrypt.return_value': 'abcd123',
        })
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["channelID"], dummy_chid.hex)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v1/abcd123")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_chid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req(router_type="simplepush",
                                     uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_post_with_app_server_key(self):
        dummy_key = "RandomKeyString"
        self.reg.request.body = json.dumps(dict(
            type="simplepush",
            key=utils.base64url_encode(dummy_key),
            data={},
        ))

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
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            call_args = self.reg.write.call_args
            ok_(call_args is not None)
            args = call_args[0]
            call_arg = json.loads(args[0])
            eq_(call_arg["channelID"], dummy_chid.hex)
            eq_(call_arg["endpoint"], "http://localhost/wpush/v2/abcd123")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_chid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.post(self._make_req(router_type="simplepush",
                                     uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_put(self):
        data = dict(token="some_token")
        frouter = self.reg.ap_settings.routers["test"]
        frouter.register = Mock()
        frouter.register.return_value = data
        self.reg.request.body = json.dumps(data)

        def handle_finish(value):
            self.reg.write.assert_called_with({})
            frouter.register.assert_called_with(
                dummy_uaid.hex,
                router_data=data,
                app_id='',
                uri=self.reg.request.uri
            )

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_uaid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.put(self._make_req(router_type='test', uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_put_bad_auth(self):
        self.reg.request.headers["Authorization"] = "Fred Smith"

        def handle_finish(value):
            self._check_error(401, 109, "Unauthorized")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_uaid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(self._make_req(router_type="test",
                                    uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_put_bad_arguments(self, *args):
        self.reg.request.headers["Authorization"] = self.auth
        data = dict(token="some_token")
        self.reg.request.body = json.dumps(dict(
            type="test",
            data=data,
        ))

        def handle_finish(value):
            self._check_error(400, 108, "Bad Request")

        def restore(*args, **kwargs):
            uuid.uuid4 = old_func

        old_func = uuid.uuid4
        uuid.uuid4 = lambda: dummy_chid
        self.finish_deferred.addBoth(restore)
        self.finish_deferred.addCallback(handle_finish)
        self.reg.put(self._make_req(uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_put_bad_router_register(self):
        frouter = self.reg.ap_settings.routers["test"]
        rexc = RouterException("invalid", status_code=402, errno=107)
        frouter.register = Mock(side_effect=rexc)

        def handle_finish(value):
            self._check_error(rexc.status_code, rexc.errno, "")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.put(self._make_req(router_type='test', uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_delete_bad_chid_value(self):
        notif = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        messages = self.reg.ap_settings.message
        messages.register_channel(dummy_uaid.hex, str(dummy_chid))
        messages.store_message(notif)
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self._check_error(410, 106, "")

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete(self._make_req("test", "test", dummy_uaid.hex,
                                       "invalid"))
        return self.finish_deferred

    def test_delete_no_such_chid(self):
        notif = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        messages = self.reg.ap_settings.message
        messages.register_channel(dummy_uaid.hex, str(dummy_chid))
        messages.store_message(notif)

        # Moto can't handle set operations of this nature so we have
        # to mock the reply
        unreg = messages.unregister_channel
        messages.unregister_channel = Mock(return_value=False)
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self._check_error(410, 106, "")

        def fixup_messages(result):
            messages.unregister_channel = unreg

        self.finish_deferred.addCallback(handle_finish)
        self.finish_deferred.addBoth(fixup_messages)
        self.reg.delete(self._make_req("test", "test",
                                       dummy_uaid.hex, str(uuid.uuid4())))
        return self.finish_deferred

    def test_delete_uaid(self):
        notif = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        notif2 = make_webpush_notification(dummy_uaid.hex, str(dummy_chid))
        messages = self.reg.ap_settings.message
        chid2 = str(uuid.uuid4())
        messages.store_message(notif)
        messages.store_message(notif2)
        self.reg.ap_settings.router.drop_user = Mock()
        self.reg.ap_settings.router.drop_user.return_value = True

        def handle_finish(value, chid2):
            # Note: Router is mocked, so the UAID is never actually
            # dropped.
            ok_(self.reg.ap_settings.router.drop_user.called)
            eq_(self.reg.ap_settings.router.drop_user.call_args_list[0][0],
                (dummy_uaid.hex,))

        self.finish_deferred.addCallback(handle_finish, chid2)
        self.reg.request.headers["Authorization"] = self.auth
        self.reg.delete(self._make_req("simplepush", "test", dummy_uaid.hex))
        return self.finish_deferred

    def test_delete_bad_uaid(self):
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self.status_mock.assert_called_with(401, reason=None)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete(self._make_req("test", "test", "invalid"))
        return self.finish_deferred

    def test_delete_orphans(self):
        self.reg.request.headers["Authorization"] = self.auth

        def handle_finish(value):
            self.status_mock.assert_called_with(410, reason=None)

        self.router_mock.drop_user = Mock()
        self.router_mock.drop_user.return_value = False
        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete(self._make_req("test", "test", dummy_uaid.hex))
        return self.finish_deferred

    def test_delete_bad_auth(self, *args):
        self.reg.request.headers["Authorization"] = "Invalid"

        def handle_finish(value):
            self.status_mock.assert_called_with(401, reason=None)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete(self._make_req("test", "test", dummy_uaid.hex))
        return self.finish_deferred

    def test_delete_bad_router(self):
        self.reg.request.headers['Authorization'] = self.auth

        def handle_finish(value):
            self.status_mock.assert_called_with(400, reason=None)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.delete(self._make_req("invalid", "test", dummy_uaid.hex))
        return self.finish_deferred

    def test_get(self):
        self.reg.request.headers['Authorization'] = self.auth
        chids = [str(dummy_chid), str(dummy_uaid)]

        def handle_finish(value):
            self.settings.message.all_channels.assert_called_with(
                str(dummy_uaid))
            call_args = json.loads(
                self.reg.write.call_args[0][0]
            )
            eq_(chids, call_args['channelIDs'])
            eq_(dummy_uaid.hex, call_args['uaid'])

        self.finish_deferred.addCallback(handle_finish)
        self.settings.message.all_channels = Mock()
        self.settings.message.all_channels.return_value = (True, chids)
        self.reg.get(self._make_req(
            router_type="test",
            router_token="test",
            uaid=dummy_uaid.hex))
        return self.finish_deferred

    def test_get_no_uaid(self):
        self.reg.request.headers['Authorization'] = self.auth

        def handle_finish(value):
            self.status_mock.assert_called_with(410, reason=None)

        self.finish_deferred.addCallback(handle_finish)
        self.reg.get(self._make_req(
            router_type="test",
            router_token="test"))
        return self.finish_deferred
