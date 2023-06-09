from typing import Dict, List, Any
import warnings

from .crypt import Crypt


class JSONCrypt(Crypt):
    """
    ### A subclass of the Crypt class that encrypts and decrypts JSON objects.

    :param enc_fernet_key: encrypted fernet key string
    :param public_key: public key
    :param private_key: private key
    :param hash_algorithm: hash algorithm to use for signing and verifying.
    Supported algorithms are: 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'.

    :attr rsa_key_strength: rsa encryption key strength.
    :attr sign_and_verify_key: whether to sign and verify the fernet key on encryption and decryption. Default to True.
    :attr suppress_warnings: whether to suppress all warnings during encryption and decryption.

    :prop rsa_key_length: rsa encryption key length.

    NOTE: The higher the encryption key strength, the longer it takes to encrypt and decrypt but the more secure it is.
    There a three levels
    """
    sign_and_verify_key = True
    suppress_warnings = False

    def j_encrypt(self, json_object: Any):
        """
        Encrypts a JSON object using the encryption key.

        :param json_object: JSON parsable object to be encrypted
        :return: encrypted JSON object
        """
        return getattr(self, f"encrypt_{type(json_object).__name__.lower()}")(json_object)

    
    def j_decrypt(self, json_object: Any):
        """
        Decrypts a JSON object using the encryption key.

        :param json_object: JSON parsable object to be decrypted
        :return: decrypted JSON object
        """
        return getattr(self, f"decrypt_{type(json_object).__name__.lower()}")(json_object)


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
        :return: decrypted string as str, int, float or bool
        """
        if not isinstance(cipher_string, str):
            raise TypeError("encrypted_string must be a string")

        type_ = "str"
        if cipher_string.startswith(':ty-') and len(cipher_string.split('\u0000')) > 1:
            type_, cipher_string = cipher_string.split('\u0000')
        r = super().decrypt(cipher_string)
        if type_ == ":ty-ndbl:":
            return int(r)
        elif type_ == ":ty-dbl:":
            return float(r)
        elif type_ == ":ty-bln:":
            return bool(r)
        return r


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


    def encrypt_tuple(self, tuple_: tuple):
        """
        Encrypts a tuple content

        :param tuple_: tuple containing contents to be encrypted
        :return: a list of encrypted content
        """
        if not self.suppress_warnings:
            warnings.warn("Tuples are not recommended for JSON", RuntimeWarning)
        if not isinstance(tuple_, tuple):
            raise TypeError(tuple_)
        e_tuple_ = self.encrypt_list(list(tuple_))
        return e_tuple_


    def encrypt_set(self, set_: set):
        """
        Encrypts a set content

        :param set_: set containing contents to be encrypted
        :return: a list of encrypted content
        """
        if not self.suppress_warnings:
            warnings.warn("Sets are not recommended for JSON", RuntimeWarning)
            print("set will be encrypted as a list")
        if not isinstance(set_, set):
            raise TypeError(set_)
        e_set_ = self.encrypt_list(list(set_))
        return e_set_


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
            encrypted_item = getattr(self, f"encrypt_{type(item).__name__.lower()}")(item)
            encrypted_list.append(encrypted_item)
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
            decrypted_item = getattr(self, f"decrypt_{type(item).__name__.lower()}")(item)
            decrypted_list.append(decrypted_item)
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
            encrypted_value = getattr(self, f"encrypt_{type(value).__name__.lower()}")(value)
            encrypted_dict[key] = encrypted_value
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
            decrypted_value = getattr(self, f"decrypt_{type(value).__name__.lower()}")(value)
            decrypted_dict[key] = decrypted_value
        return decrypted_dict        
