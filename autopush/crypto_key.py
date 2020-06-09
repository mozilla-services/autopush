"""Crypto-Key header parser and manager"""
from typing import Dict, List, Optional  # noqa


class CryptoKeyException(Exception):
    """Invalid CryptoKey"""


class CryptoKey(object):
    """Parse the Crypto-Key header per
http://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00#section-4

    The Crypto-Key header is a data store that has it's own set of rules,
    This class manages access to the Crypto-Key data. There are two ways that
    data in the Crypto-Key can be used, one by the key-id (an optional
    identifier that can be used to associate key data to other fields) and
    the data label name.

    There are a few additional functions that may be implemented. For
    instance, removing a Crypto-Key component that may not need to be
    passed on.

    """

    def __init__(self, header):
        # type: (str) -> None
        """Parse the Crypto-Key header

        :param header: Header content

        """
        self._values = []  # type: List[Dict[str, str]]
        chunks = header.split(",")
        for chunk in chunks:
            bits = chunk.split(";")
            ck_hash = {}
            for bit in bits:
                try:
                    key, value = bit.split("=", 1)
                except ValueError:
                    raise CryptoKeyException("Invalid Crypto Key value")
                ck_hash[key.strip()] = value.strip(' "')
            self._values.append(ck_hash)

    def get_keyid(self, keyid):
        # type: (str) -> Optional[Dict[str, str]]
        """Return the Crypto-Key hash referred to by a given keyid.

        For example, for a CryptoKey specified as:
        Crypto-Key: keyid="apple";foo="fruit",keyid="gorp";bar="snake"

        get_keyid("apple") would return a hash of
        {"keyid": "apple", "foo":"fruit"}

        :param keyid: The keyid to reference
        :returns: hash of the matching key data or None

        """
        for val in self._values:
            if keyid == val.get('keyid'):
                return val
        return None

    def get_label(self, label):
        # type: (str) -> Optional[str]
        """Return the Crypto-Key value referred to by a given label.

        For example, for a CryptoKey specified as:
        Crypto-Key: keyid="apple";foo="fruit",keyid="gorp";bar="snake"

        get_label("foo")
        would return a value of "fruit"

        ..note:: This presumes that "label" is unique. Otherwise it will
        only return the FIRST instance of "label". Use get_keyid() if
        you know of multiple sections containing similar labels.

        :param label: The label to reference
        :returns: Value associated with the key data or None

        """
        for val in self._values:
            if label in val:
                return val.get(label)
        return None

    @classmethod
    def parse_and_get_label(cls, header, label):
        # type: (str, str) -> Optional[str]
        """Parse the Crypto-Key header and return the value referred to
        by a given label.

        :param header: Header content
        :param label: The label to reference
        :returns: Value associated with the key data or None

        """
        try:
            ck = cls(header)
        except CryptoKeyException:
            return None
        return ck.get_label(label)

    def to_string(self):
        # type: () -> str
        """Return a reformulated Crypto-Key header string"""
        chunks = []
        for val in self._values:
            bits = []
            for key in val:
                bits.append("{}=\"{}\"".format(key, val[key]))
            chunks.append(';'.join(bits))
        return ','.join(chunks)
