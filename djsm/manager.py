from typing import Any, Dict
import os
from bs4_web_scraper.file_handler import FileHandler
import bs4_web_scraper
import warnings
from dotenv import load_dotenv, find_dotenv, dotenv_values
import string
import random
from time import sleep

from .jcrypt import JSONCrypt


SECRET_KEY_ALLOWED_CHARS = string.ascii_letters + string.digits + string.punctuation

env_variables = [
    "DJSM_SECRETS_FILE_PATH",
    "DJSM_SECRET_KEY_NAME",
    "DJSM_SECRET_KEY_FILE_PATH",
]


def find_and_load_env_var():
    """Load environment variables from .env file"""
    try:
        load_dotenv(find_dotenv('.env', raise_error_if_not_found=True), override=True)
    except Exception:
        raise EnvLoadError("Could not load environmental variables because '.env' file was not found. Create one!")


def check_setup_ok():
    """Check that an .env file is present and has been properly setup"""
    setup_ok = True
    print("DJSM: Ensuring setup is OK\n")
    try:
        print("DJSM: Searching for .env file...\n")
        find_and_load_env_var()
    except EnvLoadError:
        setup_ok = False
        print("DJSM: Could not load .env file or .env file not found!\n")
        return setup_ok

    print("DJSM: Checking that .env file has been properly setup...\n")
    env_file_dict = dotenv_values(find_dotenv(raise_error_if_not_found=True))
    if not env_file_dict.get('DJSM_SECRETS_FILE_PATH', None):
        print('DJSM: DJSM_SECRETS_FILE_PATH not set in .env file\n')
        setup_ok = False
    if setup_ok:
        print('DJSM: Setup OK!\n')
    else:
        print('DJSM: Visit https://github.com/ti-oluwa/djsm/#usage for help on how to setup DJSM\n')
    return setup_ok
 


class EnvLoadError(Exception):
    """Unable to load .env file mainly because it was not found"""


class CryptKeysNotFound(Exception):
    """Secret encryption or/and decryption keys not found"""


class DjangoJSONSecretManager:
    """
    ### Class that helps manage secrets in Django applications

    :param path_to_secret_file: path the file where secrets are stored or secrets will be stored.

    EXAMPLE:
    >>> djsm = DjangoJSONSecretManager('.secret_hidden_folder/secret_file.json')
    >>> # SECURITY WARNING: keep the secret key used in production secret!
        # generate secret key if it does not exist
    >>> SECRET_KEY = djsm.get_or_create_secret_key()
    """

    __django_secret_key_name: str = 'DJANGO_SECRET_KEY'

    def __init__(self, path_to_secret_file: str):
        if not path_to_secret_file.endswith('.json'):
            raise ValueError('Secret file must be a json file')

        self.__path_to_secret_file = path_to_secret_file
        self.__django_secret_key_file_path = os.getenv('DJSM_SECRET_KEY_FILE_PATH') if os.getenv('DJSM_SECRET_KEY_FILE_PATH') else self.__path_to_secret_file
        self.__django_secret_key_name = os.getenv('DJSM_SECRET_KEY_NAME') if os.getenv('DJSM_SECRET_KEY_NAME') else self.__django_secret_key_name


    @property
    def __path_to_key_file(self):
        return f"{os.path.dirname(self.__path_to_secret_file)}\cryptkeys.json"
    

    def __setattr__(self, __name: str, __value: Any) -> None:
        if "path" in __name:
            __value = os.path.abspath(__value)
        return super().__setattr__(__name, __value)


    def encrypt(self, secret: Dict) -> Dict:
        """
        Encrypts a secret using the encryption key.

        :param secret: secret to be encrypted
        :return: encrypted secret
        """
        if not isinstance(secret, dict):
            raise TypeError("secret must be a dict")
        
        f_key, pub_key = None, None
        try:
            crypt_keys_file_hdl = FileHandler(self.__path_to_key_file)
            crypt_keys: Dict = crypt_keys_file_hdl.read_file()
            f_key = crypt_keys.get('DJSM_FERNET_KEY', None)
            pub_key = crypt_keys.get('DJSM_RSA_PUBLIC_KEY', None)
            crypt_keys_file_hdl.close_file()
        except Exception:
            pass
        priv_key = os.getenv('DJSM_RSA_PRIVATE_KEY')

        if all([f_key, pub_key, priv_key]) == False:
            f_key, pub_key, priv_key = JSONCrypt.generate_key_as_str()
            crypt_keys = {
                'DJSM_FERNET_KEY': f_key,
                'DJSM_RSA_PUBLIC_KEY': pub_key,
            }
            crypt_keys_file_hdl = FileHandler(self.__path_to_key_file)
            crypt_keys_file_hdl.write_to_file(crypt_keys)
            crypt_keys_file_hdl.close_file()
            self.__remove_rsa_priv_key_from_env()
            env_file_hdl = self.__get_env_hdl()
            env_file_hdl.write_to_file(f'DJSM_RSA_PRIVATE_KEY = "{priv_key}"\n', write_mode='a+')
            env_file_hdl.close_file()
            self.reload_env()
            
        jcrypt = JSONCrypt.from_str(f_key, pub_key, priv_key)
        encrypted_secret = jcrypt.j_encrypt(secret)
        return encrypted_secret


    def decrypt(self, encrypted_secret: Dict) -> Dict:
        """
        Decrypts an encrypted secret using the encryption key.

        :param encrypted_secret: encrypted secret to be decrypted
        :return: decrypted secret
        """
        if not isinstance(encrypted_secret, dict):
            raise TypeError("encrypted_secret must be a dict")

        f_key, pub_key = None, None
        try:
            crypt_keys_file_hdl = FileHandler(self.__path_to_key_file)
            crypt_keys: Dict = crypt_keys_file_hdl.read_file()
            f_key = crypt_keys.get('DJSM_FERNET_KEY', None)
            pub_key = crypt_keys.get('DJSM_RSA_PUBLIC_KEY', None)
            crypt_keys_file_hdl.close_file()
        except Exception:
            pass
        priv_key = os.getenv('DJSM_RSA_PRIVATE_KEY')

        if all([f_key, pub_key, priv_key]) == False:
            raise CryptKeysNotFound("Crypt key(s) not found. Secrets will not be recoverable")

        jcrypt = JSONCrypt.from_str(f_key, pub_key, priv_key)
        decrypted_secret = jcrypt.j_decrypt(encrypted_secret)
        return decrypted_secret


    @staticmethod
    def __get_env_hdl():
        """Gets and returns the .env file FileHandler object"""
        return FileHandler(find_dotenv(raise_error_if_not_found=True), allow_any=True) 

    
    @staticmethod
    def validate_secret_key(secret_key: str):
        """Check that Django secret key is valid."""
        if not isinstance(secret_key, str):
            return False
        if len(secret_key) < 32:
            return False
        for char in secret_key:
            if char not in SECRET_KEY_ALLOWED_CHARS:
                return False
        return True

    
    @staticmethod
    def generate_django_secret_key(length: int = 50):
        """
        Return a randomly generated key of not less than 32 characters
        
        :param length: length of secret key to be generated.
        """
        if length < 32:
            raise ValueError('Secret key length cannot be less than 32 characters')
        return ''.join(random.choice(SECRET_KEY_ALLOWED_CHARS) for _ in range(length))


    def __remove_rsa_priv_key_from_env(self):
        """Removes rsa private key from .env file if present"""
        env_file_handler = self.__get_env_hdl()
        env_file_dict = dotenv_values(find_dotenv(raise_error_if_not_found=True))
        env_file_dict.pop('DJSM_RSA_PRIVATE_KEY', None)

        # Clear existing variables in .env file and re-write
        env_file_handler.clear_file()
        for key, value in env_file_dict.items():
            line = f'{key} = "{value}"\n'
            env_file_handler.write_to_file(line, write_mode='a+')
        return env_file_handler.close_file()


    def change_crypt_keys(self):
        """
        Change the encryption keys
        """
        # Get existing secrets
        secret_key = self.load_secrets(self.__django_secret_key_file_path, decrypt=True) if self.__django_secret_key_file_path else {}
        secrets = self.load_secrets(self.__path_to_secret_file, decrypt=True)

        # Delete fernet and rsa public keys in JSON file - Just delete the cryptkeys.json file
        FileHandler(self.__path_to_key_file).delete_file()
        # Delete crypt key in .env file
        self.__remove_rsa_priv_key_from_env()

        # Re-write secrets while encrypting them with new keys
        if secret_key:
            self.write_secrets(secret_key, self.__django_secret_key_file_path, encrypt=True)
        self.write_secrets(secrets, self.__path_to_secret_file, encrypt=True)
        return None
        

    def get_or_create_secret_key(self, always_generate: bool = False):
        """
        Get Django secret key or create and saves a secret key in json secret file if it is non-existent.

        The secret key will be saved to the path specified in the constructor or as specified in the
        .env file

        :param always_generate: if True, a new secret key will be generated and saved
        even if one already exists in the secret file.
        :return: secret key
        """ 
        secrets = self.load_secrets(self.__django_secret_key_file_path, decrypt=True)
        if not secrets.get(self.__django_secret_key_name, None) or always_generate:
            print("DJSM: Generating Secret Key...\n")
            secrets[self.__django_secret_key_name] = self.generate_django_secret_key()
            self.write_secrets(secrets, self.__django_secret_key_file_path, overwrite=True, encrypt=True)
            print("DJSM: New Secret Key Generated Successfully\n")

        secret_key = self.get_secret(self.__django_secret_key_name)
        if not self.validate_secret_key(secret_key):
            warnings.warn("DJSM: Invalid Secret Key Found. Replacing Secret Key...")
            # Replace secret key if the secret key is not valid
            secret_key = self.change_secret_key()
        return secret_key


    def change_secret_key(self):
        """
        Replaces Django secret key with a new one.
        """
        self.get_or_create_secret_key(always_generate=True)
        return None


    def write_secrets(self, secrets: Dict[str, Any], path_to_file: str, overwrite: bool = False, encrypt: bool = False) -> None:
        """
        Writes the secrets in the given path.

        :param path_to_file: path to file in which secrets will be written.
        :param encrypt: whether to encrypt the secrets before writing in the file. 
        :return: None.
        """
        if not isinstance(secrets, dict):
            raise TypeError('Secret must be a dictionary')

        file_hdl = FileHandler(path_to_file)
        if not file_hdl.filetype == "json":
            raise TypeError("Secret file must be a json file")

        if secrets and encrypt:
            secrets = self.encrypt(secrets)
        if overwrite:
            file_hdl.write_to_file(secrets)
        else:
            file_hdl.update_json(secrets)
        return file_hdl.close_file()

    
    def load_secrets(self, path_to_file: str, decrypt: bool = False):
        """
        Loads the secrets from the given path.

        :param path_to_file: path to file containing secrets.
        :param decrypt: whether to decrypt the secrets in the file. 
        :return: a dictionary of secrets.
        """
        try:
            file_hdl = FileHandler(path_to_file)
            if not file_hdl.filetype == "json":
                raise TypeError("Secret file must be a json file")

            secrets = file_hdl.read_file()
            file_hdl.close_file()
            if not isinstance(secrets, dict):
                raise TypeError('Secrets must be a dictionary')
            if secrets and decrypt:
                secrets = self.decrypt(secrets)

        except bs4_web_scraper.FileError:
            secrets = {}
        return secrets


    def get_secret(self, key: str) -> Any | None:
        """
        Gets secret from json secret(s) file.

        :param key: key to get from the json file(s)
        :return: secret if found, None if not
        """ 
        secrets = self.load_secrets(self.__path_to_secret_file, decrypt=True)
        if self.__django_secret_key_file_path != self.__path_to_secret_file:
            try:
                secrets.update(self.load_secrets(self.__django_secret_key_file_path, decrypt=True))
            except:
                pass
        return secrets.get(key, None)


    def update_secrets(self, new_secrets: Dict[str, Any]) -> None:
        """
        Updates secrets in json secrets file.

        :param secret: secret to write to the json file
        :return: None
        """
        if not isinstance(new_secrets, dict):
            raise TypeError('Secret must be a dictionary')
        
        secrets = self.load_secrets(self.__path_to_secret_file, decrypt=True)
        _secrets = {**secrets, **new_secrets}
        return self.write_secrets(_secrets, self.__path_to_secret_file, encrypt=True)


    def clean_up(self):
        """
        Deletes all secrets in the json secrets, and secret key files. Removes all environment variables
        set by the package.

        This method is useful when you want to delete all secrets and start afresh.
        """
        self.write_secrets({}, self.__path_to_secret_file, overwrite=True, encrypt=False)
        if self.__django_secret_key_file_path != self.__path_to_secret_file:
            self.write_secrets({}, self.__django_secret_key_file_path, overwrite=True, encrypt=False)
        self.__remove_rsa_priv_key_from_env()

        for var in env_variables:
            os.environ.pop(var, None)
        return None


    def reload_env(self):
        """
        Reloads the environment variables from the .env file.
        """
        return find_and_load_env_var()


    def clean_up_and_reload(self):
        """
        Deletes all secrets in the json secrets, and secret key files. Removes all environment variables
        set by the package and reloads the environment variables from the .env file.

        This method is useful when you want to delete all secrets and start afresh.
        """
        self.clean_up()
        return self.reload_env()



