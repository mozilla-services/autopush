"""A command-line utility that generates endpoint encryption keys."""
from cryptography.fernet import Fernet

def main():
    print "Key = %s" % Fernet.generate_key()

if __name__ == "__main__":
    main()
