import json
import uuid

import twisted.internet.base
from boto.dynamodb2.exceptions import (
    ProvisionedThroughputExceededException,
)
from cyclone.web import Application
from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_
from txstatsd.metrics.metrics import Metrics
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.trial import unittest

from autopush.settings import AutopushSettings
from autopush.websocket import (
    SimplePushServerProtocol,
    RouterHandler,
    NotificationHandler,
)


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class WebsocketTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True
        self.proto = SimplePushServerProtocol()

        settings = AutopushSettings(
            reactor,
            hostname="localhost",
            statsd_host=None,
        )
        self.proto.settings = settings
        self.proto.sendMessage = self.send_mock = Mock()
        self.proto.sendClose = self.close_mock = Mock()
        self.proto.transport = self.transport_mock = Mock()
        settings.metrics = Mock(spec=Metrics)

    def _connect(self):
        self.proto.onConnect(None)

    def _send_message(self, msg):
        self.proto.onMessage(json.dumps(msg).encode('utf8'), False)

    def _wait_for_message(self, d):
        args = self.send_mock.call_args_list
        if len(args) < 1:
            reactor.callLater(0.1, self._wait_for_message, d)
            return

        args = self.send_mock.call_args_list.pop(0)
        return d.callback(args)

    def _wait_for_close(self, d):
        if self.close_mock.call_args is not None:
            d.callback(True)
            return

        reactor.callLater(0.1, self._wait_for_close, d)

    def _check_response(self, func):
        """Waits for a message to be sent, and runs the func with it"""
        def handle_message(result):
            args, _ = result
            func(json.loads(args[0]))
        d = Deferred()
        d.addCallback(handle_message)
        self._wait_for_message(d)
        return d

    def test_reporter(self):
        from autopush.websocket import periodic_reporter
        periodic_reporter(self.proto.settings)

        # Verify metric increase of nothing
        calls = self.proto.settings.metrics.method_calls
        eq_(len(calls), 1)
        name, args, _ = calls[0]
        eq_(name, "gauge")
        eq_(args, ("update.client.connections", 0))

    def test_handeshake_sub(self):
        self.proto.settings.port = 8080
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            eq_(self.proto.factory.externalPort, None)
            return False

        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})
        self.proto.processHandshake()
        eq_(self.proto.factory.externalPort, 80)

    def test_handshake_nosub(self):
        self.proto.settings.port = 80
        self.proto.factory = Mock(externalPort=80)

        def check_subbed(s):
            eq_(self.proto.factory.externalPort, 80)
            return False

        self.proto.parent_class = Mock(**{"processHandshake.side_effect":
                                          check_subbed})
        self.proto.processHandshake()
        eq_(self.proto.factory.externalPort, 80)

    def test_binary_msg(self):
        self.proto.onMessage(b"asdfasdf", True)
        d = Deferred()
        d.addCallback(lambda x: True)
        self._wait_for_close(d)
        return d

    def test_bad_json(self):
        self.proto.onMessage("}{{bad_json!!", False)
        d = Deferred()
        d.addCallback(lambda x: True)
        self._wait_for_close(d)
        return d

    def test_no_messagetype_after_hello(self):
        self._connect()
        self.proto.uaid = "asdf"
        self._send_message(dict(data="wassup"))

        def check_result(result):
            eq_(result, True)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_unknown_messagetype(self):
        self._connect()
        self.proto.uaid = "asdf"
        self._send_message(dict(messageType="wassup"))

        def check_result(result):
            eq_(result, True)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_close_with_cleanup(self):
        self._connect()
        self.proto.uaid = "asdf"
        self.proto.settings.clients["asdf"] = self.proto

        # Stick a mock on
        self.proto._notification_fetch = Mock()
        self.proto.onClose(True, None, None)
        eq_(len(self.proto.settings.clients), 0)
        eq_(len(list(self.proto._notification_fetch.mock_calls)), 1)
        name, _, _ = self.proto._notification_fetch.mock_calls[0]
        eq_(name, "cancel")

    def test_hello(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            eq_(msg["status"], 200)
        return self._check_response(check_result)

    def test_hello_with_uaid(self):
        self._connect()
        uaid = str(uuid.uuid4())
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["uaid"], uaid)
        return self._check_response(check_result)

    def test_hello_with_uaid_no_hypen(self):
        self._connect()
        uaid = str(uuid.uuid4()).replace('-', '')
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["uaid"], uaid)
        return self._check_response(check_result)

    def test_hello_with_bad_uaid(self):
        self._connect()
        uaid = "ajsidlfjlsdjflasjjailsdf"
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        def check_result(msg):
            eq_(msg["status"], 200)
            assert msg["uaid"] != uaid
        return self._check_response(check_result)

    def test_hello_failure(self):
        self._connect()
        # Fail out the register_user call
        router = self.proto.settings.router
        router.table.connection.put_item = Mock(side_effect=KeyError)

        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            eq_(msg["status"], 503)
            eq_(msg["reason"], "error")
        return self._check_response(check_result)

    def test_hello_check_fail(self):
        self._connect()

        # Fail out the register_user call
        self.proto.settings.router.register_user = Mock(return_value=False)

        self._send_message(dict(messageType="hello", channelIDs=[]))

        def check_result(msg):
            eq_(msg["status"], 500)
            eq_(msg["reason"], "already_connected")
        return self._check_response(check_result)

    def test_hello_dupe(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_second_hello(msg):
            eq_(msg["status"], 401)
            d.callback(True)

        def check_first_hello(msg):
            eq_(msg["status"], 200)
            # Send another hello
            self._send_message(dict(messageType="hello", channelIDs=[]))
            self._check_response(check_second_hello)
        f = self._check_response(check_first_hello)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_not_hello(self):
        self._connect()
        self._send_message(dict(messageType="wooooo"))

        def check_result(result):
            eq_(result, True)
        d = Deferred()
        d.addCallback(check_result)
        self._wait_for_close(d)
        return d

    def test_ping(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()

        def check_ping_result(msg):
            eq_(msg, {})
            d.callback(True)

        def check_result(msg):
            eq_(msg["status"], 200)
            self._send_message({})
            g = self._check_response(check_ping_result)
            g.addErrback(lambda x: d.errback(x))

        f = self._check_response(check_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ping_too_many(self):
        d = self.test_ping()

        closed = Deferred()

        def ping_again(result):
            self._send_message({})
            self._wait_for_close(closed)

        d.addCallback(ping_again)
        return closed

    def test_register(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["messageType"], "register")
            assert "pushEndpoint" in msg
            d.callback(True)

        def check_hello_result(msg):
            assert "messageType" in msg
            self._send_message(dict(messageType="register",
                                    channelID=str(uuid.uuid4())))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_no_chid(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "register")
            d.callback(True)

        def check_hello_result(msg):
            assert "messageType" in msg
            self._send_message(dict(messageType="register"))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_bad_chid(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "register")
            d.callback(True)

        def check_hello_result(msg):
            assert "messageType" in msg
            self._send_message(dict(messageType="register", channelID="oof"))
            self._check_response(check_register_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_register_bad_crypto(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())

        def throw_error(*args, **kwargs):
            raise Exception("Crypto explosion")

        self.proto.settings.fernet = Mock(
            **{"encrypt.side_effect": throw_error})
        self._send_message(dict(messageType="register",
                                channelID=str(uuid.uuid4())))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_register_result(msg):
            eq_(msg["status"], 500)
            eq_(msg["messageType"], "register")
            d.callback(True)

        f = self._check_response(check_register_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_unregister(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        d.addCallback(lambda x: True)
        chid = str(uuid.uuid4())

        def check_unregister_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["channelID"], chid)
            d.callback(True)

        def check_hello_result(msg):
            eq_(msg["messageType"], "hello")
            eq_(msg["status"], 200)
            self._send_message(dict(messageType="unregister",
                                    channelID=chid))
            self._check_response(check_unregister_result)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_unregister_without_chid(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())
        self._send_message(dict(messageType="unregister"))

        d = Deferred()
        d.addCallback(lambda x: True)

        def check_unregister_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "unregister")
            d.callback(True)

        f = self._check_response(check_unregister_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_unregister_bad_chid(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())
        self._send_message(dict(messageType="unregister",
                                channelID="}{$@!asdf"))

        d = Deferred()

        def check_unregister_result(msg):
            eq_(msg["status"], 401)
            eq_(msg["messageType"], "unregister")
            d.callback(True)

        f = self._check_response(check_unregister_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_unregister_fail(self):
        patcher = patch('autopush.websocket.log', spec=True)
        mock_log = patcher.start()
        self._connect()
        self.proto.uaid = str(uuid.uuid4())
        chid = str(uuid.uuid4())

        d = Deferred()
        d.addBoth(lambda x: patcher.stop())

        # Replace storage delete with call to fail
        table = self.proto.settings.storage.table
        delete = table.delete_item

        def raise_exception(*args, **kwargs):
            # Stick the original back
            table.delete_item = delete
            raise Exception("Connection problem?")

        table.delete_item = Mock(side_effect=raise_exception)
        self._send_message(dict(messageType="unregister",
                                channelID=chid))

        def wait_for_times():
            if len(mock_log.mock_calls) > 0:
                eq_(len(mock_log.mock_calls), 1)
                d.callback(True)
                return
            reactor.callLater(0.1, wait_for_times)

        reactor.callLater(0.1, wait_for_times)
        return d

    def test_notification(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())
        chid = str(uuid.uuid4())

        # Send ourself a notification
        payload = [{"channelID": chid, "version": 10}]
        self.proto.send_notifications(payload)

        # Check the call result
        args = self.send_mock.call_args
        assert args is not None
        self.send_mock.reset_mock()

        msg = json.loads(args[0][0])
        eq_(msg["messageType"], "notification")
        assert "updates" in msg
        eq_(len(msg["updates"]), 1)
        update = msg["updates"][0]
        eq_(update["channelID"], chid)
        eq_(update["version"], 10)

        # Verify outgoing queue in sent directly
        eq_(len(self.proto.direct_updates), 1)

    def test_notification_avoid_newer_delivery(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())

        chid = str(uuid.uuid4())
        self.proto.updates_sent[chid] = 14

        # Send ourself a notification
        payload = [{"channelID": chid, "version": 10}]
        self.proto.send_notifications(payload)

        # Check the call result
        args = self.send_mock.call_args
        assert args is None

    def test_notification_retains_no_dash(self):
        self._connect()

        uaid = str(uuid.uuid4()).replace('-', '')
        chid = str(uuid.uuid4()).replace('-', '')

        storage = self.proto.settings.storage
        storage.save_notification(uaid, chid, 10)
        self._send_message(dict(messageType="hello", channelIDs=[], uaid=uaid))

        d = Deferred()

        def check_notif_result(msg):
            eq_(msg["messageType"], "notification")
            updates = msg["updates"]
            eq_(len(updates), 1)
            eq_(updates[0]["channelID"], chid)
            eq_(updates[0]["version"], 10)
            d.callback(True)

        def check_hello_result(msg):
            eq_(msg["status"], 200)

            # Now wait for the notification
            nd = self._check_response(check_notif_result)
            nd.addErrback(lambda x: d.errback(x))

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_notification_dont_deliver_after_ack(self):
        self._connect()

        uaid = str(uuid.uuid4())
        chid = str(uuid.uuid4())

        storage = self.proto.settings.storage
        storage.save_notification(uaid, chid, 10)

        self._send_message(dict(messageType="hello", channelIDs=[], uaid=uaid))

        d = Deferred()

        def wait_for_clear():
            if not self.proto.accept_notification:
                reactor.callLater(0.1, wait_for_clear)
                return

            # Accepting again
            eq_(self.proto.updates_sent, {})

            # Check that storage is clear
            notifs = storage.fetch_notifications(uaid)
            eq_(len(notifs), 0)
            d.callback(True)

        def check_notif_result(msg):
            eq_(msg["messageType"], "notification")
            updates = msg["updates"]
            eq_(len(updates), 1)
            eq_(updates[0]["channelID"], chid)
            eq_(updates[0]["version"], 10)
            eq_(self.proto.accept_notification, False)
            # Send our ack
            self._send_message(dict(messageType="ack",
                                    updates=[{"channelID": chid,
                                              "version": 10}]))

            # Wait for updates to be cleared and notifications accepted again
            reactor.callLater(0.1, wait_for_clear)

        def check_hello_result(msg):
            eq_(msg["status"], 200)

            # Now wait for the notification
            nd = self._check_response(check_notif_result)
            nd.addErrback(lambda x: d.errback(x))

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ack(self):
        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[]))

        d = Deferred()
        chid = str(uuid.uuid4())

        # stick a notification to ack in
        self.proto.direct_updates[chid] = 12
        self.proto.updates_sent[chid] = 12

        def check_hello_result(msg):
            eq_(msg["status"], 200)

            # Send our ack
            self._send_message(dict(messageType="ack",
                                    updates=[{"channelID": chid,
                                              "version": 12}]))

            # Verify it was cleared out
            eq_(len(self.proto.updates_sent), 0)
            eq_(len(self.proto.direct_updates), 0)
            d.callback(True)

        f = self._check_response(check_hello_result)
        f.addErrback(lambda x: d.errback(x))
        return d

    def test_ack_fails_first_time(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())

        class FailFirst(object):
            def __init__(self):
                self.tries = 0

            def __call__(self, *args, **kwargs):
                if self.tries == 0:
                    self.tries += 1
                    return False
                else:
                    return True

        self.proto.settings.storage = Mock(
            **{"delete_notification.side_effect": FailFirst()})

        chid = str(uuid.uuid4())

        # stick a notification to ack in
        self.proto.updates_sent[chid] = 12

        # Send our ack
        self._send_message(dict(messageType="ack",
                                updates=[{"channelID": chid,
                                          "version": 12}]))

        # Ask for a notification check again
        self.proto.process_notifications = Mock()
        self.proto._check_notifications = True

        d = Deferred()

        def wait_for_delete():
            calls = self.transport_mock.mock_calls
            if len(calls) < 2:
                reactor.callLater(0.1, wait_for_delete)
                return

            eq_(self.proto.updates_sent, {})
            process_calls = self.proto.process_notifications.mock_calls
            eq_(len(process_calls), 1)
            d.callback(True)

        reactor.callLater(0.1, wait_for_delete)
        return d

    def test_ack_missing_updates(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())
        self.proto.sendJSON = Mock()

        self._send_message(dict(messageType="ack"))

        calls = self.proto.sendJSON.call_args_list
        eq_(len(calls), 0)

    def test_ack_missing_chid_version(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())

        self._send_message(dict(messageType="ack",
                                updates=[{"something": 2}]))

        calls = self.send_mock.call_args_list
        eq_(len(calls), 0)

    def test_ack_untracked(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())

        self._send_message(dict(messageType="ack",
                                updates=[{"channelID": str(uuid.uuid4()),
                                          "version": 10}]))

        calls = self.send_mock.call_args_list
        eq_(len(calls), 0)

    def test_process_notifications(self):
        twisted.internet.base.DelayedCall.debug = True
        self._connect()
        self.proto.uaid = str(uuid.uuid4())

        # Swap out fetch_notifications
        self.proto.settings.storage.fetch_notifications = Mock(
            return_value=[]
        )

        self.proto.process_notifications()

        # Grab a reference to it
        notif_d = self.proto._notification_fetch

        # Run it again to trigger the cancel
        self.proto.process_notifications()

        # Tag on our own to follow up
        d = Deferred()

        # Ensure we catch error outs from either call
        notif_d.addErrback(lambda x: d.errback(x))

        def wait(result):
            eq_(self.proto._notification_fetch, None)
            d.callback(True)
        self.proto._notification_fetch.addCallback(wait)
        self.proto._notification_fetch.addErrback(lambda x: d.errback(x))
        return d

    def test_process_notification_error(self):
        self._connect()
        self.proto.uaid = str(uuid.uuid4())

        def throw_error(*args, **kwargs):
            raise ProvisionedThroughputExceededException(None, None)

        self.proto.settings.storage = Mock(
            **{"fetch_notifications.side_effect": throw_error})
        self.proto.process_notifications()
        self.proto._check_notifications = True

        # Now replace process_notifications so it won't be
        # run again
        self.proto.process_notifications = Mock()
        d = Deferred()

        def wait_for_process():
            calls = self.proto.process_notifications.mock_calls
            if len(calls) > 0:
                self.flushLoggedErrors()
                d.callback(True)
            else:
                reactor.callLater(0.1, wait_for_process)

        def check_error(result):
            eq_(self.proto._check_notifications, False)

            # Now schedule the checker to wait for the next
            # process_notifications call
            reactor.callLater(0.1, wait_for_process)

        self.proto._notification_fetch.addBoth(check_error)
        return d

    def test_notification_results(self):
        # Populate the database for ourself
        uaid = str(uuid.uuid4())
        chid = str(uuid.uuid4())
        storage = self.proto.settings.storage
        storage.save_notification(uaid, chid, 12)

        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        d = Deferred()

        def check_notifs(msg):
            eq_(msg["messageType"], "notification")
            eq_(len(msg["updates"]), 1)
            update = msg["updates"][0]
            eq_(update["version"], 12)
            eq_(update["channelID"], chid)
            d.callback(True)

        def check_result(msg):
            eq_(msg["status"], 200)
            eq_(msg["messageType"], "hello")

            # Now wait for the notification results
            nd = self._check_response(check_notifs)
            nd.addErrback(lambda x: d.errback(x))

        cd = self._check_response(check_result)
        cd.addErrback(lambda x: d.errback(x))
        return d

    def test_notification_dont_deliver(self):
        # Populate the database for ourself
        uaid = str(uuid.uuid4())
        chid = str(uuid.uuid4())
        storage = self.proto.settings.storage
        storage.save_notification(uaid, chid, 12)

        self._connect()
        self._send_message(dict(messageType="hello", channelIDs=[],
                                uaid=uaid))

        d = Deferred()

        def check_mock_call():
            calls = self.proto.process_notifications.mock_calls
            if len(calls) < 1:
                reactor.callLater(0.1, check_mock_call)
                return

            eq_(len(calls), 1)
            d.callback(True)

        def check_call(result):
            send_calls = self.send_mock.mock_calls
            # There should be one, for the hello response
            # No notifications should've been delivered after
            # this notifiation check
            eq_(len(send_calls), 1)

            # Now we wait for the mock call to run
            reactor.callLater(0.1, check_mock_call)

        # Run immediately after hello was processed
        def after_hello(result):
            # Setup updates_sent to avoid a notification send
            self.proto.updates_sent[chid] = 14

            # Notification check has started, indicate to check
            # notifications again
            self.proto._check_notifications = True

            # Now replace process_notifications so it won't be
            # run again
            self.proto.process_notifications = Mock()

            # Chain our check for the call
            self.proto._notification_fetch.addBoth(check_call)
            self.proto._notification_fetch.addErrback(lambda x: d.errback(x))

        self.proto._register.addCallback(after_hello)
        self.proto._register.addErrback(lambda x: d.errback(x))
        return d


class RouterHandlerTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True

        self.ap_settings = AutopushSettings(
            reactor,
            hostname="localhost",
            statsd_host=None,
        )
        self.ap_settings.metrics = Mock(spec=Metrics)
        h = RouterHandler
        h.ap_settings = self.ap_settings
        self.mock_request = Mock()
        self.handler = h(Application(), self.mock_request)
        self.handler.set_status = self.status_mock = Mock()
        self.handler.write = self.write_mock = Mock()

    def test_client_connected(self):
        uaid = str(uuid.uuid4())
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(len(client_mock.mock_calls), 1)

    def test_client_not_connected(self):
        uaid = str(uuid.uuid4())
        self.mock_request.body = "{}"
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(len(self.status_mock.mock_calls), 1)
        eq_(self.status_mock.call_args, ((404,),))

    def test_client_connected_but_busy(self):
        uaid = str(uuid.uuid4())
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        client_mock.accept_notification = False
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(len(self.status_mock.mock_calls), 1)
        eq_(self.status_mock.call_args, ((503,),))


class NotificationHandlerTestCase(unittest.TestCase):
    def setUp(self):
        twisted.internet.base.DelayedCall.debug = True

        self.ap_settings = AutopushSettings(
            reactor,
            hostname="localhost",
            statsd_host=None,
        )
        self.ap_settings.metrics = Mock(spec=Metrics)
        h = NotificationHandler
        h.ap_settings = self.ap_settings
        self.mock_request = Mock()
        self.handler = h(Application(), self.mock_request)
        self.handler.set_status = self.status_mock = Mock()
        self.handler.write = self.write_mock = Mock()

    def test_connected_and_free(self):
        uaid = str(uuid.uuid4())
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(len(client_mock.mock_calls), 1)

    def test_connected_and_busy(self):
        uaid = str(uuid.uuid4())
        self.mock_request.body = "{}"
        self.ap_settings.clients[uaid] = client_mock = Mock()
        client_mock.accept_notification = False
        client_mock._check_notifications = False
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(client_mock._check_notifications, True)
        eq_(self.status_mock.call_args, ((202,),))

    def test_not_connected(self):
        uaid = str(uuid.uuid4())
        self.mock_request.body = "{}"
        self.handler.put(uaid)
        eq_(len(self.write_mock.mock_calls), 1)
        eq_(self.status_mock.call_args, ((404,),))
