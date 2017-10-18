import socket
import ssl
from twisted.trial import unittest

from autopush.ssl import (
    monkey_patch_ssl_wrap_socket,
    ssl_wrap_socket_cached,
    undo_monkey_patch_ssl_wrap_socket
)


class SSLContextCacheTestCase(unittest.TestCase):

    def setUp(self):
        # XXX: test_main doesn't cleanup after itself
        undo_monkey_patch_ssl_wrap_socket()

    def test_monkey_patch_ssl_wrap_socket(self):
        assert ssl.wrap_socket is not ssl_wrap_socket_cached
        orig = ssl.wrap_socket
        monkey_patch_ssl_wrap_socket()
        self.addCleanup(undo_monkey_patch_ssl_wrap_socket)

        assert ssl.wrap_socket is ssl_wrap_socket_cached
        undo_monkey_patch_ssl_wrap_socket()
        assert ssl.wrap_socket is orig

    def test_ssl_wrap_socket_cached(self):
        monkey_patch_ssl_wrap_socket()
        self.addCleanup(undo_monkey_patch_ssl_wrap_socket)

        s1 = socket.create_connection(('search.yahoo.com', 443))
        s2 = socket.create_connection(('google.com', 443))
        ssl1 = ssl.wrap_socket(s1, do_handshake_on_connect=False)
        ssl2 = ssl.wrap_socket(s2, do_handshake_on_connect=False)
        assert ssl1.context is ssl2.context
