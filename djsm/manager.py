from typing import Any, Dict
from django.core.management import utils
import os
from bs4_web_scraper.file_handler import FileHandler
import bs4_web_scraper
import warnings


from .jcrypt import JSONCrypt



class EnvLoadError(Exception):
    pass


class DjangoJSONSecretManager:

    django_secret_key_name: str = 'django_secret_key'
    django_secret_key_file_path: str = None

    def __init__(self, path_to_secret_file: str):
        if not path_to_secret_file.endswith('.json'):
            raise ValueError('Secret file must be a json file')

        self.path_to_secret_file = path_to_secret_file
        self.django_secret_key_file_path = os.environ.get('DJANGO_SECRET_KEY_FILE_PATH') if os.environ.get('DJANGO_SECRET_KEY_FILE_PATH', None) else self.path_to_secret_file
        self.django_secret_key_name = os.environ.get('DJANGO_SECRET_KEY_NAME') if os.environ.get('DJANGO_SECRET_KEY_NAME', None) else self.django_secret_key_name

    @property
    def path_to_key_file(self):
        return f"{os.path.dirname(self.path_to_secret_file)}\cryptkeys.json"
    
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
        
        f_key, pub_key, priv_key = self._get_crypt_keys()

        if all([f_key, pub_key, priv_key]) == False:
            f_key, pub_key, priv_key = JSONCrypt.generate_key_as_str()
            crypt_keys = {
                'f_key': f_key,
                'pub_key': pub_key,
                'priv_key': priv_key,
            }
            key_file_hdl = FileHandler(self.path_to_key_file)
            key_file_hdl.write_to_file(crypt_keys)
            key_file_hdl.close_file()
            
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

        f_key, pub_key, priv_key = self._get_crypt_keys()
        if all([f_key, pub_key, priv_key]) == False:
            raise ValueError("Crypt key(s) not found")

        jcrypt = JSONCrypt.from_str(f_key, pub_key, priv_key)
        decrypted_secret = jcrypt.j_decrypt(encrypted_secret)
        return decrypted_secret


    def _get_crypt_keys(self):
        """
        Returns the encryption keys
        """
        keys = {}
        try:
            key_file_hdl = FileHandler(self.path_to_key_file)
            keys: Dict = key_file_hdl.read_file()
            key_file_hdl.close_file()
        except Exception:
            pass
        return keys.get('f_key', None), keys.get('pub_key', None), keys.get('priv_key', None)


    def change_crypt_keys(self):
        """Change the encryption keys"""
        secret_key = self._load_secrets(self.django_secret_key_file_path) if self.django_secret_key_file_path else {}
        secrets = self._load_secrets(self.path_to_secret_file)
        FileHandler(self.path_to_key_file).delete_file()

        if secret_key:
            self._write_secrets(secret_key, self.django_secret_key_file_path, encrypt=True)
        self._write_secrets(secrets, self.path_to_secret_file, encrypt=True)
        return None
        

    def generate_secret_key(self, always_generate: bool = False):
        """
        Generates and saves a secret key in json secret file if it is non-existent.

        the secret key will be saved to the path specified in the constructor
        or the path specified in the `DJANGO_SECRET_KEY_FILE_PATH` environment variable.

        Args::
            always_generate: if True, a new secret key will be generated and saved
            even if one already exists in the secret file.
        :return: secret key
        """ 
        secrets = self._load_secrets(self.django_secret_key_file_path)
        if not secrets.get(self.django_secret_key_name, None) or always_generate:
            print("DJSM: Generating Secret Key")
            secrets[self.django_secret_key_name] = utils.get_random_secret_key()
            self._write_secrets(secrets, self.django_secret_key_file_path, overwrite=True)
        return self.get_secret_key()


    def _write_secrets(self, secrets: Dict[str, Any], path_to_file: str | None = None, overwrite: bool = False, encrypt: bool = True) -> None:
        if not isinstance(secrets, dict):
            raise TypeError('Secret must be a dictionary')
        path_to_file = self.path_to_secret_file if not path_to_file else path_to_file
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

    
    def _load_secrets(self, path_to_file: str | None = None, decrypt: bool = True):
        path_to_file = self.path_to_secret_file if not path_to_file else path_to_file
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


    @property
    def secrets(self) -> Dict:
        """
        Gets secrets from a json secret files

        :return: secrets
        """
        secrets = self._load_secrets()
        if self.django_secret_key_file_path != self.path_to_secret_file:
            try:
                secrets.update(self._load_secrets(self.django_secret_key_file_path))
            except:
                pass
        return secrets


    def get_secret(self, key: str) -> Any | None:
        """
        Gets secret from json secret file.

        :param key: key to get from the json file
        :return: secret if found, None if not found
        :raises ValueError: if the file is not a json file
        """ 
        return self.secrets.get(key, None)


    def update_secrets(self, new_secrets: Dict[str, Any]) -> None:
        """
        Updates secrets in json secrets file.

        :param secret: secret to write to the json file
        :return: None
        """
        if not isinstance(new_secrets, dict):
            raise TypeError('Secret must be a dictionary')
        
        secrets = self._load_secrets()
        _secrets = {**secrets, **new_secrets}
        return self._write_secrets(_secrets)


    def get_secret_key(self):
        """
        Gets secret key from json secrets. If the key is not found or invalid, a new one is generated.

        :return: secret key
        """
        secret_key = self.get_secret(self.django_secret_key_name)
        if not self.validate_secret_key(secret_key):
            warnings.warn("DJSM: Invalid Secret Key Found. Generating New Secret Key")
            # Generate a new secret key if the secret key is not valid
            secret_key = self.generate_secret_key(always_generate=True)
        return secret_key if self.validate_secret_key(secret_key) else None


    @staticmethod
    def validate_secret_key(secret_key: str):
        if not isinstance(secret_key, str):
            return False
        if len(secret_key) != 50:
            return False
        return True


