import unittest

from nose.tools import (eq_, ok_)

from autopush.crypto_key import CryptoKey


class CryptoKeyTestCase(unittest.TestCase):

    valid_key = (
        'keyid="p256dh";dh="BDw9T0eImd4ax818VcYqDK_DOhcuDswKero'
        'YyNkdhYmygoLSDlSiWpuoWYUSSFxi25cyyNTR5k9Ny93DzZc0UI4",'
        'p256ecdsa="BF92zdI_AKcH5Q31_Rr-04bPqOHU_Qg6lAawHbvfQrY'
        'xV_vIsAsHSyaiuyfofvxT8ZVIXccykd4V2Z7iJVfreT8"')

    def test_parse(self):
        ckey = CryptoKey(self.valid_key)
        eq_(ckey.get_keyid("p256dh"),
            {"keyid": "p256dh",
             "dh": "BDw9T0eImd4ax818VcYqDK_DOhcuDswKero"
                   "YyNkdhYmygoLSDlSiWpuoWYUSSFxi25cyyNTR5k9Ny93DzZc0UI4"})
        eq_(ckey.get_label("p256ecdsa"),
            "BF92zdI_AKcH5Q31_Rr-04bPqOHU_Qg6lAawHbvfQrY"
            "xV_vIsAsHSyaiuyfofvxT8ZVIXccykd4V2Z7iJVfreT8")
        ok_(ckey.get_keyid("missing") is None)
        ok_(ckey.get_label("missing") is None)

    def test_parse_lenient(self):
        ckey = CryptoKey(self.valid_key.replace('"', ''))
        str = ckey.to_string()
        ckey2 = CryptoKey(str)
        ok_(ckey.get_keyid("p256dh"), ckey2.get_keyid("p256dh"))
        ok_(ckey.get_label("p256ecdsa") is not None)
        ok_(ckey.get_label("p256ecdsa"), ckey2.get_label("p256ecdsa"))

    def test_string(self):
        ckey = CryptoKey(self.valid_key)
        str = ckey.to_string()
        ckey2 = CryptoKey(str)
        ok_(ckey.get_keyid("p256dh"), ckey2.get_keyid("p256dh"))
        ok_(ckey.get_label("p256ecdsa") is not None)
        ok_(ckey.get_label("p256ecdsa"), ckey2.get_label("p256ecdsa"))
