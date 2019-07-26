import json

import pytest
import treq
from mock import Mock

from oauth2client.service_account import ServiceAccountCredentials
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.trial import unittest
from twisted.web.http_headers import Headers

from autopush.exceptions import RouterException
from autopush.router.fcmv1client import FCMv1, FCMAuthenticationError


class FCMv1TestCase(unittest.TestCase):

    def setUp(self):
        self._m_request = Deferred()
        self._m_response = Mock(spec=treq.response._Response)
        self._m_response.code = 200
        self._m_response.headers = Headers()
        self._m_resp_text = Deferred()
        self._m_response.text.return_value = self._m_resp_text
        self.fcm = FCMv1(project_id="fcm_test")
        self.fcm._sender = Mock(spec=treq.request)
        self.fcm.svc_cred = Mock(spec=ServiceAccountCredentials)
        atoken = Mock()
        atoken.access_token = "access_token"
        self.fcm.svc_cred.get_access_token.return_value = atoken
        self.fcm._sender.return_value = self._m_request
        self.m_payload = {"ttl": 60, "data_message": "some content"}
        self._success = {
            u"name": (u'projects/fir-bridgetest/messages/'
                      u'0:1544652984769917%0aa51ebcf9fd7ecd')
        }
        self._failure = {
            u'error': {
                u'status': u'INVALID_ARGUMENT',
                u'message': (u'The registration token is not a valid '
                             u'FCM registration token'),
                u'code': 400,
                u'details': [
                    {
                        u'errorCode': u'INVALID_ARGUMENT',
                        u'@type': (u'type.googleapis.com/google.firebase'
                                   u'.fcm.v1.FcmError')},
                    {u'fieldViolations': [
                        {u'field': u'message.token',
                         u'description': (u'The registration token is not '
                                          u'a valid FCM registration token')}],
                        u'@type': u'type.googleapis.com/google.rpc.BadRequest'}
                ]
            }
        }

    @inlineCallbacks
    def test_send(self):
        content = json.dumps(self._success)
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        result = yield self.fcm.send("token", self.m_payload)
        assert result.success == 1

    @inlineCallbacks
    def test_bad_reply(self):
        self._m_response.code = 400
        content = json.dumps("Invalid JSON")
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        with pytest.raises(RouterException) as ex:
            yield self.fcm.send("token", self.m_payload)
        assert ex.value.status_code == 500

    @inlineCallbacks
    def test_fail_400(self):
        self._m_response.code = 400
        content = json.dumps(self._failure)
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        with pytest.raises(RouterException) as ex:
            yield self.fcm.send("token", self.m_payload)
        assert ex.value.status_code == 500
        assert "Server error: INVALID_ARGUMENT:" in str(ex.value)

    @inlineCallbacks
    def test_fail_401(self):
        self._m_response.code = 401
        content = "Unauthorized"
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        with pytest.raises(FCMAuthenticationError):
            yield self.fcm.send("token", self.m_payload)

    @inlineCallbacks
    def test_fail_500(self):
        self._m_response.code = 500
        content = "OMG"
        self._m_response.headers.addRawHeader('Retry-After', "123")
        self._m_resp_text.callback(content)
        self._m_request.callback(self._m_response)
        result = yield self.fcm.send("token", self.m_payload)
        assert result.retry_after == "123"
