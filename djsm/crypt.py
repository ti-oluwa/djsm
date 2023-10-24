import rsa
import base64
import pickle
from cryptography.fernet import Fernet
from typing import Any, Dict, List

from .exceptions import KeyVerificationError, EncryptionError, DecryptionError


SUPPOTED_RSA_KEY_LENGTHS = [1024, 2048, 4096]

ENCRYPTION_LEVELS = [
    (1, 1024),
    (2, 2048),
    (3, 4096)
]



class BaseCrypt:
    """
    #### Base class for encryption and decryption text using Fernet + RSA Encryption

    :attr rsa_key_strength: rsa encryption key strength. Default to 1.
    :attr sign_and_verify_key: whether to sign and verify the fernet key on encryption and decryption. Default to True.
    :prop rsa_key_length: rsa encryption key length

    NOTE: The higher the encryption key strength, the longer it takes to encrypt and decrypt but the more secure it is.
    There a three levels
    """
    rsa_key_strength = 1
    sign_and_verify_key = True
    hash_algorithm = 'SHA-512'
    __slots__ = (
        "__id__",  
        "enc_fernet_key",
        "rsa_pub_key",
        "rsa_priv_key"
    )

    def __init__(
            self, 
            enc_fernet_key: bytes, 
            rsa_public_key: rsa.PublicKey, 
            rsa_private_key: rsa.PrivateKey, 
            hash_algorithm: str = 'SHA-512'
        ):
        """
        Initializes the Crypt object

        :param enc_fernet_key: encrypted fernet key string
        :param public_key: public key
        :param private_key: private key
        :param hash_algorithm: hash algorithm to use for signing and verifying. Supported algorithms are: 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'.
        """
        self.enc_fernet_key = enc_fernet_key
        self.rsa_pub_key = rsa_public_key
        self.rsa_priv_key = rsa_private_key
        self.hash_algorithm = hash_algorithm
        self.__id__ = id(self)


    def __eq__(self, o: object):
        if not isinstance(o, self.__class__):
            return False
        return self.__dict__ == o.__dict__


    @classmethod
    def _get_rsa_key_length(cls) -> int:
        return ENCRYPTION_LEVELS[cls.rsa_key_strength - 1][1]

    @property
    def rsa_key_length(self):
        return self._get_rsa_key_length()


    @classmethod
    def generate_keys(cls):
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
    def _load_rsa_key_from_str(
        rsa_key_str: str, 
        type_: str = "public", 
        encoding: str = 'utf-8'
    ):
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
    def _encrypt_f_key(
        cls, 
        f_key: bytes, 
        rsa_pub_key: rsa.PublicKey, 
        rsa_priv_key: rsa.PrivateKey = None
    ):
        enc_f_key = rsa.encrypt(f_key, rsa_pub_key)
        if cls.sign_and_verify_key and rsa_priv_key:
            signature = cls._rsa_sign_fernet_key(f_key, rsa_priv_key)
            enc_f_key = b'\u0000'.join([enc_f_key, signature])
        return enc_f_key


    @classmethod
    def _decrypt_f_key(
        cls, 
        enc_f_key: bytes, 
        rsa_priv_key: rsa.PrivateKey, 
        rsa_pub_key: rsa.PublicKey = None
    ):
        if cls.sign_and_verify_key:
            enc_f_key, signature = enc_f_key.split(b'\u0000')
        dec_f_key = rsa.decrypt(enc_f_key, rsa_priv_key)
        if cls.sign_and_verify_key and rsa_pub_key:
            is_verified = cls._rsa_verify_fernet_key(dec_f_key, signature, rsa_pub_key)
            if not is_verified:
                raise KeyVerificationError('Fernet key cannot be verified. Might have been tampered with.')
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
    def _rsa_verify_fernet_key(
        cls, 
        fernet_key: bytes, 
        signature: bytes, 
        rsa_pub_key: rsa.PublicKey
    ) -> bool:
        """
        Verifies a decrypted fernet key using the public key

        :param fernet_key: fernet key to be verified
        :param signature: signature to be verified
        :param rsa_pub_key: rsa public key
        """
        return rsa.verify(fernet_key, signature, rsa_pub_key) == cls.hash_algorithm


    @classmethod
    def generate_keys_as_str(cls, encoding: str = 'utf-8'):
        """
        Generates a key tuple containing strings.
        
        :param encoding: encoding to be used to encode the key strings
        :return: encrypted Fernet key, rsa public key and rsa private key used to encrypted the Fernet key
        :rtype : str
        """
        enc_f_key, pub_key, priv_key = cls.generate_keys()
        enc_f_key_str = cls._enc_f_key_to_str(enc_f_key, encoding=encoding)
        pub_key_str = cls._rsa_key_to_str(pub_key, encoding=encoding)
        priv_key_str = cls._rsa_key_to_str(priv_key, encoding=encoding)
        return enc_f_key_str, pub_key_str, priv_key_str


    @classmethod
    def from_str(
        cls, 
        enc_fernet_key: str, 
        rsa_public_key: str, 
        rsa_private_key: str, 
        encoding: str = 'utf-8'
    ):
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
        del f_key
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
        del f_key
        string = string_bytes.decode(encoding=encoding)
        return string



class Crypt(BaseCrypt):
    """
    #### Encrypts and decrypts Python objects using Fernet + RSA Encryption

    :attr rsa_key_strength: rsa encryption key strength. Default to 1.
    :attr sign_and_verify_key: whether to sign and verify the fernet key on encryption and decryption. Default to True.
    :prop rsa_key_length: rsa encryption key length.

    NOTE: The higher the encryption key strength, the longer it takes to encrypt and decrypt but the more secure it is.
    There a three levels. Empty strings and None are not encrypted.
    """

    def encrypt(self, object_: Any):
        """
        Encrypts a Python object.

        :param object_: Python object to be encrypted
        :return: encrypted Python object
        """
        if object_ is not None and object_ != "":
            try:
                return getattr(self, f"encrypt_{type(object_).__name__.lower()}")(object_)
            except AttributeError:
                return self._encrypt_object(object_)
            except Exception as e:
                raise EncryptionError(e)
        return object_


    def decrypt(self, object_: Any):
        """
        Decrypts a Python object.

        :param object_: Python object to be decrypted
        :return: decrypted Python object
        """
        if object_ is not None and object_ != "":
            try:
                return getattr(self, f"decrypt_{type(object_).__name__.lower()}")(object_)
            except Exception as e:
                raise DecryptionError(e)
        return object_


    def encrypt_str(self, string: str) -> str:
        """
        Encrypts a string using the encryption key.

        :param string: string to be encrypted
        :return: encrypted string and signature
        """
        if not isinstance(string, str):
            raise TypeError("string must be a string")
        r = super().encrypt(string)
        return r


    def decrypt_str(self, cipher_string: str):
        """
        Decrypts an encrypted string using the encryption key.

        :param cipher_string: encrypted string to be decrypted
        :param signature: signature of the encrypted string
        :return: decrypted object
        """
        if not isinstance(cipher_string, str):
            raise TypeError("encrypted_string must be a string")

        type_ = None
        split = cipher_string.split('\u0000')
        if cipher_string.startswith(':ty-') and len(split) > 1:
            if len(split) == 2:
                type_, cipher_str = split
                r = super().decrypt(cipher_str)
            else:
                type_ = split[0]
                rem_cipher_str = "\u0000".join(split[1:])
                r = self.decrypt(rem_cipher_str)
        else:
            r = super().decrypt(cipher_string)

        if not type_:
            return str(r)
        if type_ == ":ty-ndbl:":
            return int(r)
        elif type_ == ":ty-dbl:":
            return float(r)
        elif type_ == ":ty-bln:":
            return bool(r)
        elif type_ == ":ty-b:":
            return base64.urlsafe_b64decode(r.encode())
        elif type_ == ":ty-obj:":
            return pickle.loads(r)


    def encrypt_int(self, int_: int):
        """
        Encrypts an integer

        :param int_: integer to be encrypted
        :return: encrypted integer as a string
        """
        if not isinstance(int_, int):
            raise TypeError(int_)
        e_int_ = self.encrypt_str(str(int_))
        return f":ty-ndbl:\u0000{e_int_}"


    def encrypt_float(self, float_: float):
        """
        Encrypts a float

        :param float_: float to be encrypted
        :return: encrypted float as a string
        """
        if not isinstance(float_, float):
            raise TypeError(float_)
        e_float_ = self.encrypt_str(str(float_))
        return f":ty-dbl:\u0000{e_float_}"


    def encrypt_bool(self, bool_: bool):
        """
        Encrypts a boolean

        :param bool_: boolean to be encrypted
        :return: encrypted boolean as a string
        """
        if not isinstance(bool_, bool):
            raise TypeError(bool_)
        e_bool_ = self.encrypt_str(str(bool_))
        return f":ty-bln:\u0000{e_bool_}"


    def encrypt_bytes(self, bytes_: bytes):
        """
        Encrypts a bytes content

        :param bytes_: bytes containing contents to be encrypted
        :return: string of encrypted bytes content
        """
        if not isinstance(bytes_, bytes):
            raise TypeError(bytes_)
        bytes_str = base64.urlsafe_b64encode(bytes_).decode()
        enc_bytes_str = self.encrypt(bytes_str)
        return f":ty-b:\u0000{enc_bytes_str}"


    def encrypt_tuple(self, tuple_: tuple):
        """
        Encrypts a tuple content

        :param tuple_: tuple containing contents to be encrypted
        :return: tuple with contents encrypted
        """
        if not isinstance(tuple_, tuple):
            raise TypeError(tuple_)
        return tuple(self.encrypt_list(list(tuple_)))
    

    def decrypt_tuple(self, cipher_tuple: tuple):
        """
        Decrypts a tuple of encrypted content

        :param cipher_tuple: tuple of encrypted content to be decrypted
        :return: tuple of decrypted content
        """
        if not isinstance(cipher_tuple, tuple):
            raise TypeError(cipher_tuple)
        return tuple(self.decrypt_list(list(cipher_tuple)))


    def encrypt_set(self, set_: set):
        """
        Encrypts a set content

        :param set_: set containing contents to be encrypted
        :return: set with contents encrypted
        """
        if not isinstance(set_, set):
            raise TypeError(set_)
        return set(self.encrypt_list(list(set_)))
    

    def decrypt_set(self, cipher_set: set):
        """
        Decrypts a set of encrypted content

        :param cipher_set: set of encrypted content to be decrypted
        :return: set of decrypted content
        """
        if not isinstance(cipher_set, set):
            raise TypeError(cipher_set)
        return set(self.decrypt_list(list(cipher_set)))


    def encrypt_list(self, list_: List):
        """
        Encrypts a list content

        :param secret: list containing contents to be encrypted
        :return: list of encrypted content
        """
        if not isinstance(list_, list):
            raise TypeError(list_)
        encrypted_list = []
        for item in list_:
            if item is not None and item != "":
                encrypted_item = self.encrypt(item)
                encrypted_list.append(encrypted_item)
            else:
                encrypted_list.append(item)
        return encrypted_list

    
    def decrypt_list(self, cipher_list: List):
        """
        Decrypts a list of encrypted content

        :param cipher_list: list of encrypted content to be decrypted
        :return: list of decrypted content
        """
        if not isinstance(cipher_list, list):
            raise TypeError(cipher_list)
        decrypted_list = []
        for item in cipher_list:
            if item is not None and item != "":
                decrypted_item = self.decrypt(item)
                decrypted_list.append(decrypted_item)
            else:
                decrypted_list.append(item)
        return decrypted_list

    
    def encrypt_dict(self, dict_: Dict):
        """
        Encrypts a dict content

        :param dict_: dictionary containing contents to be encrypted
        :return: dictionary of encrypted content
        """
        if not isinstance(dict_, dict):
            raise TypeError(dict_)
        encrypted_dict = {}
        for key, value in dict_.items():
            if value is not None and value != "":
                encrypted_value = self.encrypt(value)
                encrypted_dict[key] = encrypted_value
            else:
                encrypted_dict[key] = value
        return encrypted_dict

    
    def decrypt_dict(self, cipher_dict: Dict):
        """
        Decrypts dict with encrypted content

        :param cipher_list: list of encrypted content to be decrypted
        :return: list of decrypted content
        """
        if not isinstance(cipher_dict, dict):
            raise TypeError(cipher_dict)
        decrypted_dict = {}
        for key, value in cipher_dict.items():
            if value is not None and value != "":
                decrypted_value = self.decrypt(value)
                decrypted_dict[key] = decrypted_value
            else:
                decrypted_dict[key] = value
        return decrypted_dict  
    

    def _encrypt_object(self, object_: object):
        """
        Encrypts a Python class object

        :param object_: Python class object to be encrypted
        :return: encrypted Python class object
        """
        dumped_obj = pickle.dumps(object_)
        encrypted_obj = self.encrypt(dumped_obj)
        return f":ty-obj:\u0000{encrypted_obj}"


    
