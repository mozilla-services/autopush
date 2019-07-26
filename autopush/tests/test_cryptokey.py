import unittest

import pytest

from autopush.crypto_key import CryptoKey, CryptoKeyException


class CryptoKeyTestCase(unittest.TestCase):

    valid_key = (
        'keyid="p256dh";dh="BDw9T0eImd4ax818VcYqDK_DOhcuDswKero'
        'YyNkdhYmygoLSDlSiWpuoWYUSSFxi25cyyNTR5k9Ny93DzZc0UI4",'
        'p256ecdsa="BF92zdI_AKcH5Q31_Rr-04bPqOHU_Qg6lAawHbvfQrY'
        'xV_vIsAsHSyaiuyfofvxT8ZVIXccykd4V2Z7iJVfreT8"')

    def test_parse(self):
        ckey = CryptoKey(self.valid_key)
        assert ckey.get_keyid("p256dh") == {
            "keyid": "p256dh",
            "dh": "BDw9T0eImd4ax818VcYqDK_DOhcuDswKero"
                  "YyNkdhYmygoLSDlSiWpuoWYUSSFxi25cyyNTR5k9Ny93DzZc0UI4"}
        assert ckey.get_label("p256ecdsa") == (
            "BF92zdI_AKcH5Q31_Rr-04bPqOHU_Qg6lAawHbvfQrY"
            "xV_vIsAsHSyaiuyfofvxT8ZVIXccykd4V2Z7iJVfreT8")
        assert ckey.get_keyid("missing") is None
        assert ckey.get_label("missing") is None

    def test_parse_and_get_label(self):
        assert CryptoKey.parse_and_get_label(self.valid_key, "p256ecdsa") == (
            "BF92zdI_AKcH5Q31_Rr-04bPqOHU_Qg6lAawHbvfQrY"
            "xV_vIsAsHSyaiuyfofvxT8ZVIXccykd4V2Z7iJVfreT8")
        assert CryptoKey.parse_and_get_label(self.valid_key, "missing") is None
        assert CryptoKey.parse_and_get_label("invalid key", "missing") is None

    def test_parse_invalid(self):
        with pytest.raises(CryptoKeyException) as ex:
            CryptoKey("invalid key")
        assert str(ex.value) == "Invalid Crypto Key value"

    def test_parse_different_order(self):
        ckey = CryptoKey(self.valid_key)
        ckey2 = CryptoKey(','.join(self.valid_key.split(',')[::-1]))
        assert ckey.get_keyid("p256dh") == ckey2.get_keyid("p256dh")
        assert ckey.get_label("p256ecdsa") is not None
        assert ckey.get_label("p256ecdsa") == ckey2.get_label("p256ecdsa")

    def test_parse_lenient(self):
        ckey = CryptoKey(self.valid_key.replace('"', ''))
        str = ckey.to_string()
        ckey2 = CryptoKey(str)
        assert ckey.get_keyid("p256dh") == ckey2.get_keyid("p256dh")
        assert ckey.get_label("p256ecdsa") is not None
        assert ckey.get_label("p256ecdsa") == ckey2.get_label("p256ecdsa")

    def test_string(self):
        ckey = CryptoKey(self.valid_key)
        str = ckey.to_string()
        ckey2 = CryptoKey(str)
        assert ckey.get_keyid("p256dh") == ckey2.get_keyid("p256dh")
        assert ckey.get_label("p256ecdsa") is not None
        assert ckey.get_label("p256ecdsa") == ckey2.get_label("p256ecdsa")
