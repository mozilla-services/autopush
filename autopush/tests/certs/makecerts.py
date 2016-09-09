# coding: utf-8

import uuid
from inspect import getsource
from datetime import datetime

from OpenSSL.crypto import (
    FILETYPE_PEM, TYPE_RSA, X509, PKey, dump_privatekey, dump_certificate)

SHABREAK = 51


def make_cert(filename, cacert=None, cakey=None):
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    cert = X509()
    subject = cert.get_subject()

    subject.C = b"TR"
    subject.ST = b"Çorum"
    subject.L = b"Başmakçı"
    subject.CN = b"localhost"
    subject.O = b"Mozilla Test"
    subject.OU = b"Autopush Test %s" % filename
    subject.emailAddress = b"pjenvey@mozilla.com"

    #cert.set_serial_number(datetime.now().toordinal())
    cert.set_serial_number(uuid.uuid4().int)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 100)

    cert.set_pubkey(key)

    if not cacert:
        # self sign
        cacert = cert
        cakey = key
    cert.set_issuer(cacert.get_subject())
    cert.sign(cakey, 'sha1')

    with open(filename, 'wb') as fp:
        fp.write(dump_privatekey(FILETYPE_PEM, key))
        fp.write(dump_certificate(FILETYPE_PEM, cert))
    return cert, key


def save_sha256(sha256):
    import __main__
    source = getsource(__main__)
    source = source.splitlines(True)[:-2]
    with open('makecerts.py', 'wb') as fp:
        fp.writelines(source)
        fp.write("CLIENT1_SHA256 = ('%s'\n" % sha256[:SHABREAK])
        fp.write("                  '%s')\n" % sha256[SHABREAK:])


def main():
    # self signed
    server, serverkey = make_cert("server.pem")
    client1, _ = make_cert("client1.pem", cacert=server, cakey=serverkey)
    make_cert("client2.pem", cacert=server, cakey=serverkey)
    save_sha256(client1.digest('sha256'))


if __name__ == '__main__':
    main()

CLIENT1_SHA256 = ('DE:D2:72:A4:7A:B2:4B:D1:F9:45:B2:4E:6C:71:F3:7F:F8:'
                  '0C:F2:47:88:A6:F9:51:B0:DE:EF:66:E2:42:8C:34')
