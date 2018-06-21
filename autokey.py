"""A command-line utility that generates endpoint encryption keys."""
from cryptography.fernet import Fernet


def main():
    print "CRYPTO_KEY=\"%s\"" % Fernet.generate_key()
