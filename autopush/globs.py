from cryptography.fernet import Fernet

# Big global clients hash
clients = {}

CRYPTO_KEY = "5z855nRkhg8jpWjSdNGO9zGQYyfA7vVNsQmDai7OQkk="
MIN_PING_INTERVAL = 20
MAX_DATA_PAYLOAD = 4096

fernet = Fernet(CRYPTO_KEY)
