import getpass
import hashlib

from crypto import decrypt
from errors import InvalidEncryptionKeyError
from helper_functions import get_config_value

VALID_SERVER_PERMISSION_NAMES = [
    "manage_backups",
    "manage_ip_whitelist",
    "view_logged_requests",
    "manage_sensitive_fields",
    "manage_encrypted_files",
    "manage_encrypted_fields",
    "manage_alerts",
    "manage_api_keys",
    "manage_users",
    "view_api_documentation",
    "manage_encryption_key",
]

_encryption_config = get_config_value("encryption-config")

if _encryption_config is not None:
    kek_passphrase = getpass.getpass("Encryption passphrase: ")
    kek = hashlib.scrypt(
        kek_passphrase.encode("UTF-8"),
        salt=bytes.fromhex(_encryption_config["kek-salt"]),
        n=32768,
        r=8,
        p=1,
        maxmem=33816576,
        dklen=32,
    )

    if hashlib.sha3_512(kek).hexdigest() == _encryption_config["kek-hash"]:
        ENCRYPTION_KEY = decrypt(
            bytes.fromhex(_encryption_config["encrypted-dek"]),
            kek,
        )
    else:
        raise InvalidEncryptionKeyError
else:
    ENCRYPTION_KEY = None
