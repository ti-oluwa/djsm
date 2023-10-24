
class EnvLoadError(Exception):
    """Unable to load .env file mainly because it was not found"""


class CryptKeysNotFound(Exception):
    """Secret encryption or/and decryption keys not found"""


class KeyVerificationError(Exception):
    """Fernet key is not verified. Might have been tampered with."""


class EncryptionError(Exception):
    """Error encrypting object."""


class DecryptionError(Exception):
    """Error decrypting object."""

