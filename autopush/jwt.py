import base64
import binascii
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from pyasn1.error import PyAsn1Error
from twisted.logger import Logger


def repad(string):
    # type: (str) -> str
    """Adds padding to strings for base64 decoding"""
    if len(string) % 4:
        string += '===='[len(string) % 4:]
    return string


class VerifyJWT(object):
    """Minimally verify a Vapid JWT object.

        Why hand roll? Most python JWT libraries either use a python elliptic
        curve library directly, or call one that does, or is abandoned, or a
        dozen other reasons.

        After spending half a day looking for reasonable replacements, I
        decided to just write the functions we need directly.

        THIS IS NOT A FULL JWT REPLACEMENT.

    """

    @staticmethod
    def extract_signature(auth):
        # type: (str) -> tuple()
        """Fix the JWT auth token.

        The JWA spec defines the signature to be a pair of 32octet encoded
        longs.
        The `ecdsa` library signs using a raw, 32octet pair of values (s, r).
        Cryptography, which uses OpenSSL, uses a DER sequence of (s, r).
        This function converts the raw ecdsa to DER.

        :param auth: A JWT authorization token.
        :type auth: str

        :return tuple containing the signature material and signature

        """
        payload, asig = auth.encode('utf8').rsplit(".", 1)
        sig = base64.urlsafe_b64decode(repad(asig))
        if len(sig) != 64:
            return payload, sig

        encoded = utils.encode_dss_signature(
            s=int(binascii.hexlify(sig[32:]), 16),
            r=int(binascii.hexlify(sig[:32]), 16)
        )
        return payload, encoded

    @staticmethod
    def decode(token, key):
        # type (str, str) -> dict()
        """Decode a web token into a assertion dictionary.

        This attempts to rectify both ecdsa and openssl generated
        signatures. We use the built-in cryptography library since it wraps
        libssl and is faster than the python only approach.

        :param token: VAPID auth token
        :type token: str
        :param key: bitarray containing public key
        :type key: str or bitarray

        :return dict of the VAPID claims

        :raise InvalidSignature

        """
        # convert the signature if needed.
        try:
            sig_material, signature = VerifyJWT.extract_signature(token)
            pkey = ec.EllipticCurvePublicNumbers.from_encoded_point(
                ec.SECP256R1(),
                key
            ).public_key(default_backend())
            # NOTE: verify() will take any string as the signature. It appears
            # to be doing lazy verification and matching strings rather than
            # comparing content values. If the signatures start failing for
            # some unknown reason in the future, decode the signature and
            # make sure it matches how we're reconstructing it.
            # This will raise an InvalidSignature exception if failure.
            # It will be captured externally.
            pkey.verify(
                signature,
                sig_material.encode('utf8'),
                ec.ECDSA(hashes.SHA256()))
            return json.loads(
                base64.urlsafe_b64decode(
                    repad(sig_material.split('.')[1]).encode('utf8')))
        except (ValueError, TypeError, binascii.Error, PyAsn1Error):
            raise InvalidSignature()
        except Exception:  # pragma: no cover
            Logger().failure("Unexpected error processing JWT")
            raise InvalidSignature()
