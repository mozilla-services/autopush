# encoding: utf-8

import os
import uuid

from OpenSSL.crypto import (
    FILETYPE_PEM, PKey, TYPE_RSA, X509, X509Extension,
    dump_certificate, dump_privatekey)


def make_cert(filename, cacert=None, cakey=None):
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    cert = X509()
    subject = cert.get_subject()

    subject.C = b"TR"
    subject.ST = b"Çorum"
    subject.L = b"Başmakçı"
    subject.CN = b"localhost"
    subject.O = b"Mozilla Test"  # noqa: E741
    subject.OU = b"Autopush Test %s" % filename
    subject.emailAddress = b"otto.push@example.com"
    subjectAltName = X509Extension(b'subjectAltName', False, b'DNS:localhost')
    cert.add_extensions([subjectAltName])

    cert.set_serial_number(uuid.uuid4().int)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 100)

    cert.set_pubkey(key)

    if not cacert:
        # self sign
        cacert = cert
        cakey = key
    cert.set_issuer(cacert.get_subject())
    cert.sign(cakey, 'sha256')

    with open(filename, 'wb') as fp:
        fp.write(dump_privatekey(FILETYPE_PEM, key))
        fp.write(dump_certificate(FILETYPE_PEM, cert))
    return cert, key


def main():
    certsdir = os.path.dirname(__file__)

    # server.pem is self signed
    server, serverkey = make_cert(os.path.join(certsdir, "server.pem"))

    client1, _ = make_cert(os.path.join(certsdir, "client1.pem"),
                           cacert=server, cakey=serverkey)
    make_cert(os.path.join(certsdir, "client2.pem"),
              cacert=server, cakey=serverkey)

    with open(os.path.join(certsdir, "client1_sha256.txt"), 'w') as fp:
        fp.write(client1.digest('sha256'))


if __name__ == '__main__':
    main()
