
class EnvLoadError(Exception):
    """Unable to load .env file mainly because it was not found"""


class CryptKeysNotFound(Exception):
    """Secret encryption or/and decryption keys not found"""
