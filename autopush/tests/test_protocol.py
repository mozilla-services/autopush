from mock import Mock
from nose.tools import eq_
from twisted.trial import unittest
from twisted.web.client import Response

from autopush.protocol import IgnoreBody


class ProtocolTestCase(unittest.TestCase):
    def test_ignore(self):
        mock_reason = Mock()
        mock_reason.check.return_value = True

        def deliverBody(proto):
            proto.dataReceived("some data to ignore")
            proto.connectionLost(mock_reason)
        mock_response = Mock(spec=Response)
        mock_response.deliverBody.side_effect = deliverBody
        d = IgnoreBody.ignore(mock_response)

        def verifyResponse(result):
            eq_(result, mock_response)
            eq_(len(mock_reason.mock_calls), 1)

        d.addCallback(verifyResponse)
        return d

    def test_ignore_check_false(self):
        mock_reason = Mock()
        mock_reason.check.return_value = False

        def deliverBody(proto):
            proto.dataReceived("some data to ignore")
            proto.connectionLost(mock_reason)
        mock_response = Mock(spec=Response)
        mock_response.deliverBody.side_effect = deliverBody
        d = IgnoreBody.ignore(mock_response)

        def verifyResponse(result):
            eq_(result.value, mock_reason)
            eq_(len(mock_reason.mock_calls), 1)

        d.addErrback(verifyResponse)
        return d
