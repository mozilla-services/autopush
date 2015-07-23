from mock import Mock, patch
from nose.tools import eq_

from autopush.waker import UDPWake, WakeException
import unittest


class WakerTestCase(unittest.TestCase):
    def test_new(self):
        # Websocket version:
        protocol = Mock()
        killer = Mock()
        args = dict(arg1='123', arg2='456')
        t1 = UDPWake(protocol=protocol, timeout=123, kill_func=killer, **args)
        eq_(t1.protocol, protocol)
        eq_(t1.timeout, 123)
        eq_(t1.kill_func, killer)
        eq_(t1.kill_args, args)

        self.assertRaises(ValueError, UDPWake, protocol=None, timeout=123)

        #endpoint
        host = "http://example.com"
        cert = "test.pem"
        t2 = UDPWake(host=host, cert=cert)
        eq_(t2.endpoint, host)
        eq_(t2.cert, cert)

    @patch('time.time', return_value=1234567890)
    def test_set_active(self, ftime):
        t1 = UDPWake()
        t1.set_active()
        eq_(t1.idle, 1234567890000)

    def test_register(self):
        t1 = UDPWake()
        #Yep, purely for coverage
        t1.register(None)

    @patch('time.time', return_value=1234567890)
    def test_check_idle(self, ftime):
        t1 = UDPWake()
        t1.idler = Mock()
        t1.idler.cancel = Mock()
        t1.protocol = Mock()
        t1.protocol.deferToLater = Mock()
        t1.timeout=10
        t1.idle = 1234567790000
        t1.kill_func = Mock()
        t1.kill_args = dict(arg1='foo', arg2='bar')
        t1.check_idle()
        assert(t1.kill_func.called)
        assert(t1.idler.cancel.called)
        t1.kill_func.assert_called_with(arg1="foo", arg2="bar")
        eq_(t1.protocol.deferToLater.called, False)

        # and now try it when idle is not expired
        t1.idle = 1234567881000
        t1.check_idle()
        assert(t1.protocol.deferToLater.called)

        # Don't break main message processing
        t1.protocol = None
        t1.check_idle()

    @patch('requests.post')
    def test_send_wake(self, fpost):
        t1 = UDPWake(host="http://example.com", cert="example.pem")
        t1.info = dict(data={"key1": "value1"})
        resp = Mock()
        resp.status_code = 200
        fpost.return_value = resp
        t1.send_wake(None)
        fpost.assert_called_with('http://example.com', data='key1=value1',
                                 cert='example.pem')
        resp.status_code = 500
        self.assertRaises(WakeException, t1.send_wake)



