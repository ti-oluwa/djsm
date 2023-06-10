import rsa
import base64
from cryptography.fernet import Fernet


SUPPOTED_RSA_KEY_LENGTHS = [1024, 2048, 4096]

ENCRYPTION_LEVELS = [
    (1, 1024),
    (2, 2048),
    (3, 4096)
]


class KeyVerificationError(Exception):
    """Fernet key is not verified. Might have been tampered with."""


class Crypt:
    """
    ### Encrypts and decrypts text using Fernet + RSA Encryption

    :param enc_fernet_key: encrypted fernet key string
    :param public_key: public key
    :param private_key: private key
    :param hash_algorithm: hash algorithm to use for signing and verifying.
    Supported algorithms are: 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'.

    :attr rsa_key_strength: rsa encryption key strength
    :attr sign_and_verify_key: whether to sign and verify the fernet key on encryption and decryption.

    :prop rsa_key_length: rsa encryption key length

    NOTE: The higher the encryption key strength, the longer it takes to encrypt and decrypt but the more secure it is.
    There a three levels
    """
    rsa_key_strength = 1
    sign_and_verify_key = False
    hash_algorithm = 'SHA-512'

    def __init__(self, enc_fernet_key: bytes, rsa_public_key: rsa.PublicKey, rsa_private_key: rsa.PrivateKey, hash_algorithm: str = 'SHA-512'):
        self.enc_fernet_key = enc_fernet_key
        self.rsa_pub_key = rsa_public_key
        self.rsa_priv_key = rsa_private_key
        self.hash_algorithm = hash_algorithm

    @classmethod
    def _get_rsa_key_length(cls) -> int:
        return ENCRYPTION_LEVELS[cls.rsa_key_strength - 1][1]

    @property
    def rsa_key_length(self):
        return self._get_rsa_key_length()

    @classmethod
    def generate_key(cls):
        """
        Generates key tuple.

        :returns: a tuple of encrypted Fernet key, the rsa public key and rsa private key used to encrypt the Fernet key
        """
        f_key = Fernet.generate_key()
        nbits = cls._get_rsa_key_length()
        pub_key, priv_key = rsa.newkeys(nbits)
        enc_f_key = cls._encrypt_f_key(f_key, pub_key, priv_key)
        return enc_f_key, pub_key, priv_key

    @staticmethod
    def _rsa_key_to_str(rsa_key: rsa.PublicKey | rsa.PrivateKey, encoding: str = 'utf-8'):
        rsa_key_str = base64.urlsafe_b64encode(rsa_key.save_pkcs1()).decode(encoding=encoding)
        return rsa_key_str

    @staticmethod
    def _load_rsa_key_from_str(rsa_key_str: str, type_: str = "public", encoding: str = 'utf-8'):
        key_bytes = base64.urlsafe_b64decode(rsa_key_str.encode(encoding=encoding))
        if type_ == 'private':
            return rsa.PrivateKey.load_pkcs1(key_bytes)
        elif type_ == 'public':
            return rsa.PublicKey.load_pkcs1(key_bytes)
        raise ValueError('type_ must be either "private" or "public"')

    @staticmethod
    def _enc_f_key_to_str(enc_f_key_bytes: bytes, encoding: str = 'utf-8'):
        return base64.urlsafe_b64encode(enc_f_key_bytes).decode(encoding=encoding)

    @staticmethod
    def _load_enc_f_key_from_str(enc_f_key_str: str, encoding: str = 'utf-8'):
        return base64.urlsafe_b64decode(enc_f_key_str.encode(encoding=encoding))

    @classmethod
    def _encrypt_f_key(cls, f_key: bytes, rsa_pub_key: rsa.PublicKey, rsa_priv_key: rsa.PrivateKey = None):
        enc_f_key = rsa.encrypt(f_key, rsa_pub_key)
        if cls.sign_and_verify_key and rsa_priv_key:
            signature = cls._rsa_sign_fernet_key(f_key, rsa_priv_key)
            enc_f_key = b'\u0000'.join([enc_f_key, signature])
        return enc_f_key

    @classmethod
    def _decrypt_f_key(cls, enc_f_key: bytes, rsa_priv_key: rsa.PrivateKey, rsa_pub_key: rsa.PublicKey = None):
        if cls.sign_and_verify_key:
            enc_f_key, signature = enc_f_key.split(b'\u0000')
        dec_f_key = rsa.decrypt(enc_f_key, rsa_priv_key)
        if cls.sign_and_verify_key and rsa_pub_key:
            is_verified = cls._rsa_verify_fernet_key(dec_f_key, signature, rsa_pub_key)
            if not is_verified:
                raise KeyVerificationError
        return dec_f_key

    @classmethod
    def _rsa_sign_fernet_key(cls, fernet_key: bytes, rsa_priv_key: rsa.PrivateKey):
        """
        Signs the fernet key using the rsa private key

        :param fernet_key: fernet key to be signed
        :param rsa_priv_key: rsa private key
        :return: signature
        """
        signature = rsa.sign(fernet_key, rsa_priv_key, cls.hash_algorithm)
        return signature

    @classmethod
    def _rsa_verify_fernet_key(cls, fernet_key: bytes, signature: bytes, rsa_pub_key: rsa.PublicKey) -> bool:
        """
        Verifies a decrypted fernet key using the public key

        :param fernet_key: fernet key to be verified
        :param signature: signature to be verified
        :param rsa_pub_key: rsa public key
        """
        return rsa.verify(fernet_key, signature, rsa_pub_key) == cls.hash_algorithm

    @classmethod
    def generate_key_as_str(cls, encoding: str = 'utf-8'):
        """
        Generates a key tuple containing strings.
        
        :param encoding: encoding to be used to encode the key strings
        :return: encrypted Fernet key, rsa public key and rsa private key used to encrypted the Fernet key
        :rtype : str
        """
        enc_f_key, pub_key, priv_key = cls.generate_key()
        enc_f_key_str = cls._enc_f_key_to_str(enc_f_key, encoding=encoding)
        pub_key_str = cls._rsa_key_to_str(pub_key, encoding=encoding)
        priv_key_str = cls._rsa_key_to_str(priv_key, encoding=encoding)
        return enc_f_key_str, pub_key_str, priv_key_str

    @classmethod
    def from_str(cls, enc_fernet_key: str, rsa_public_key: str, rsa_private_key: str, encoding: str = 'utf-8'):
        """
        Creates an Crypt object from key strings

        :param enc_fernet_key: encrypted fernet key string
        :param public_key: public key string
        :param private_key: private key string
        :param encoding: encoding used to encode the key strings
        :return: Crypt object
        """
        enc_fernet_key = cls._load_enc_f_key_from_str(enc_fernet_key, encoding=encoding)
        pub_key: rsa.PublicKey = cls._load_rsa_key_from_str(rsa_public_key, 'public', encoding=encoding)
        priv_key: rsa.PrivateKey = cls._load_rsa_key_from_str(rsa_private_key, 'private', encoding=encoding)
        return cls(enc_fernet_key, pub_key, priv_key)

    def encrypt(self, string: str, encoding: str = 'utf-8'):
        """
        Encrypts a string using the fernet key

        :param string: string to be encrypted
        :param encoding: encoding to be used to decode and encode the string
        :return: encrypted string
        """
        if not isinstance(string, str):
            raise TypeError('string must be of type str')

        f_key = self._decrypt_f_key(self.enc_fernet_key, self.rsa_priv_key, self.rsa_pub_key)
        string_bytes = string.encode(encoding=encoding)
        cipher_bytes = Fernet(f_key).encrypt(string_bytes)
        cipher_string = cipher_bytes.decode(encoding=encoding)
        return cipher_string

    def decrypt(self, cipher_string: str, encoding: str = 'utf-8'):
        """
        Decrypts a string using the fernet key

        :param cipher_string: string to be decrypted
        :param encoding: encoding to be used to decode and encode the string
        :return: decrypted string
        """
        if not isinstance(cipher_string, str):
            raise TypeError('cipher_string must be of type str')

        f_key = self._decrypt_f_key(self.enc_fernet_key, self.rsa_priv_key, self.rsa_pub_key)
        cipher_bytes = cipher_string.encode(encoding=encoding)
        string_bytes = Fernet(f_key).decrypt(cipher_bytes)
        string = string_bytes.decode(encoding=encoding)
        return string
