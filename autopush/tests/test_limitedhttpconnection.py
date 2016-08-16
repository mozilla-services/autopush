from io import BytesIO

from mock import Mock
from twisted.trial import unittest
from nose.tools import eq_

from autopush.web.limitedhttpconnection import (
    LimitedHTTPConnection,
)


class TestLimitedHttpConnection(unittest.TestCase):
    def test_lineRecieved(self):
        mock_transport = Mock()
        conn = LimitedHTTPConnection()
        conn.factory = Mock()
        conn.factory.settings = {}
        conn.makeConnection(mock_transport)
        conn._on_headers = Mock()

        conn.maxHeaders = 2
        conn.lineReceived("line 1")
        eq_(conn._headersbuffer, ["line 1\r\n"])
        conn.lineReceived("line 2")
        conn.lineReceived("line 3")
        mock_transport.loseConnection.assert_called()
        conn.lineReceived("")
        eq_(conn._headersbuffer, [])
        conn._on_headers.assert_called()
        eq_(conn._on_headers.call_args[0][0],
            "line 1\r\nline 2\r\n")

    def test_rawDataReceived(self):
        mock_transport = Mock()
        conn = LimitedHTTPConnection()
        conn.factory = Mock()
        conn.factory.settings = {}
        conn.makeConnection(mock_transport)
        conn._on_headers = Mock()
        conn._on_request_body = Mock()
        conn._contentbuffer = BytesIO()

        conn.maxData = 10
        conn.rawDataReceived("12345")
        conn._contentbuffer = BytesIO()
        conn.content_length = 3
        conn.rawDataReceived("12345")
        eq_(False, mock_transport.loseConnection.called)
        conn._on_request_body.assert_called()
        conn.rawDataReceived("12345678901")
        mock_transport.loseConnection.assert_called()
