import json

import pytest
import treq
from mock import Mock
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.trial import unittest
from twisted.web.http_headers import Headers

from autopush.exceptions import RouterException
from autopush.router import gcmclient


class GCMClientTestCase(unittest.TestCase):

    def setUp(self):
        self.gcm = gcmclient.GCM(api_key="FakeValue")
        self.gcm._sender = Mock(spec=treq.request)
        self._m_request = Deferred()
        self.gcm._sender.return_value = self._m_request
        self._m_response = Mock(spec=treq.response._Response)
        self._m_response.code = 200
        self._m_response.headers = Headers()
        self._m_resp_text = Deferred()
        self._m_response.text.return_value = self._m_resp_text
        self.m_payload = gcmclient.JSONMessage(
            registration_ids="some_reg_id",
            collapse_key="coll_key",
            time_to_live=60,
            dry_run=False,
            data={"foo": "bar"}
        )

    @inlineCallbacks
    def test_send(self):
        content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 1,
            "failure": 0,
            "canonical_ids": 0,
            "results": [
                {
                    "message_id": "0:1510011451922224%7a0e7efbaab8b7cc"
                }
            ]
        })
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        result = yield self.gcm.send(self.m_payload)
        assert len(result.failed) == 0
        assert len(result.canonicals) == 0
        assert (len(result.success) == 1
                and self.m_payload.registration_ids[0] in result.success)

    @inlineCallbacks
    def test_canonical(self):
        content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 1,
            "failure": 0,
            "canonical_ids": 1,
            "results": [
                {
                    "message_id": "0:1510011451922224%7a0e7efbaab8b7cc",
                    "registration_id": "otherId",
                }
            ]
        })
        # pre-trigger the callbacks
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        # and then trigger the main thread
        result = yield self.gcm.send(self.m_payload)
        assert len(result.failed) == 0
        assert len(result.canonicals) == 1
        assert (len(result.success) == 1
                and self.m_payload.registration_ids[0] in result.success)

    def test_bad_jsonmessage(self):
        with pytest.raises(RouterException):
            self.m_payload = gcmclient.JSONMessage(
                registration_ids=None,
                collapse_key="coll_key",
                time_to_live=60,
                dry_run=False,
                data={"foo": "bar"}
            )

    @inlineCallbacks
    def test_fail_invalid(self):
        content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 0,
            "failure": 1,
            "canonical_ids": 0,
            "results": [
                {
                    "error": "InvalidRegistration"
                }
            ]
        })
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        self._m_request.return_value = self._m_response
        result = yield self.gcm.send(self.m_payload)
        assert len(result.failed) == 1
        assert len(result.success) == 0

    @inlineCallbacks
    def test_fail_unavailable(self):
        self._m_response.code = 200
        content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 0,
            "failure": 1,
            "canonical_ids": 0,
            "results": [
                {
                    "error": "Unavailable"
                }
            ]
        })
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        result = yield self.gcm.send(self.m_payload)
        assert len(result.unavailable) == 1
        assert len(result.success) == 0

    @inlineCallbacks
    def test_fail_not_registered(self):
        content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 0,
            "failure": 1,
            "canonical_ids": 0,
            "results": [
                {
                    "error": "NotRegistered"
                }
            ]
        })
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        result = yield self.gcm.send(self.m_payload)
        assert len(result.not_registered) == 1
        assert len(result.success) == 0

    @inlineCallbacks
    def test_fail_bad_response(self):
        content = json.dumps({
            "multicast_id": 5174939174563864884,
            "success": 0,
            "failure": 1,
            "canonical_ids": 0,
        })
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        with pytest.raises(RouterException):
            yield self.gcm.send(self.m_payload)

    @inlineCallbacks
    def test_fail_400(self):
        self._m_response.code = 400
        content = msg = "Invalid JSON"
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        with pytest.raises(RouterException) as ex:
            yield self.gcm.send(self.m_payload)
        assert ex.value.status_code == 500
        assert ex.value.message == "Server error: {}".format(msg)

    @inlineCallbacks
    def test_fail_404(self):
        self._m_response.code = 404
        content = msg = "Invalid URL"
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        with pytest.raises(RouterException) as ex:
            yield self.gcm.send(self.m_payload)
        assert ex.value.status_code == 500
        assert ex.value.message == "Server error: {}".format(msg)

    @inlineCallbacks
    def test_fail_401(self):
        self._m_response.code = 401
        content = "Unauthorized"
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        with pytest.raises(gcmclient.GCMAuthenticationError):
            yield self.gcm.send(self.m_payload)

    @inlineCallbacks
    def test_fail_500(self):
        self._m_response.code = 500
        content = "OMG"
        self._m_response.headers.addRawHeader('Retry-After', "123")
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        result = yield self.gcm.send(self.m_payload)
        assert 'some_reg_id' in result.retry_message.registration_ids
        assert result.retry_after == "123"
