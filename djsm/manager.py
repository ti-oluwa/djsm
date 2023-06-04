from typing import Any, Dict, List
from django.core.management import utils
import os
import json
import warnings
from dotenv import load_dotenv, find_dotenv


class EnvLoadError(Exception):
    pass

# load environment variables from .env file
try:
    load_dotenv(find_dotenv('.env', raise_error_if_not_found=True), override=True)
except Exception as e:
    raise EnvLoadError("Could not load environmental variables because '.env' file was not found. Create one!")


class DjangoJSONSecretManager:

    django_secret_key_name: str = 'django_secret_key'
    django_secret_key_file_path: str = None
    secret_key_fallbacks: List[str] = []

    def __init__(self, path_to_secret_file: str):
        if not path_to_secret_file.endswith('.json'):
            raise ValueError('Secret file must be a json file')

        self.path_to_secret_file = path_to_secret_file
        self.django_secret_key_file_path = self.path_to_secret_file
        self.create_secrets_file(self.path_to_secret_file)

    
    def __setattr__(self, __name: str, __value: Any) -> None:
        if "path" in __name:
            __value = os.path.abspath(__value)
        return super().__setattr__(__name, __value)


    def generate_secret_key(self):
        """
        Generates and saves a secret key in json secret file if it is non-existent.

        the secret key will be saved to the path specified in the constructor
        :return: secret key
        """
        
        self.create_secrets_file(self.django_secret_key_file_path)
        secrets = self._load_secrets(self.django_secret_key_file_path)
        if not secrets.get(self.django_secret_key_name, None):
            print("DJSM: Generating Secret Key")
            secrets[self.django_secret_key_name] = utils.get_random_secret_key()
            self._write_secrets(secrets, self.django_secret_key_file_path)
        return self.get_secret_key()


    def create_secrets_file(self, path_to_secret_file: str) -> bool:
        """
        Creates a json file for storing secrets if it does not exist yet.

        :param path_to_secret_file: path to the json file
        :return: True if file was created else False
        """

        os.makedirs(os.path.dirname(path_to_secret_file), exist_ok=True)
        if os.path.exists(path_to_secret_file):
            loadable: bool = self._check_json_loadable(path_to_secret_file)
            if not loadable:
                # Overwrite file content
                self._write_secrets({}, path_to_secret_file, 'w')
            return False
        else:
            self._write_secrets({}, path_to_secret_file, 'x')
        return True


    def _write_secrets(self, secrets: Dict[str, Any], path_to_file: str | None = None, mode: str = 'w') -> None:
        if not isinstance(secrets, dict):
            raise TypeError('Secret must be a dictionary')
        path_to_file = self.path_to_secret_file if not path_to_file else path_to_file

        with open(path_to_file, mode=mode, encoding='utf-8') as secrets_file:
            secrets_file.write(json.dumps(secrets, indent=4))
        return None

    
    def _load_secrets(self, path_to_file: str | None = None) -> Dict | None:
        path_to_file = self.path_to_secret_file if not path_to_file else path_to_file

        loadable = self._check_json_loadable(path_to_file)
        if not loadable:
            return None
        with open(path_to_file, mode='r', encoding='utf-8') as secrets_file:
            secrets = json.load(secrets_file)
        return secrets


    @staticmethod
    def _check_json_loadable(path: str) -> bool:
        """
        Checks that the `path` points to a JSON serializable file. 

        :param path: path to the file to be checked
        :return: True if JSON serializable else False
        """
        with open(path, 'r') as file:
            try:
                _ = json.load(file)
                return True
            except json.decoder.JSONDecodeError:
                pass
        file.close()
        return False


    @property
    def secrets(self) -> Dict:
        """
        Gets secrets from a json secret files

        :return: secrets
        """ 
        secrets = self._load_secrets()
        if self.django_secret_key_file_path != self.path_to_secret_file:
            secrets.update(self._load_secrets(self.django_secret_key_file_path))
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


    def get_secret_key(self) -> str | None:
        """
        Gets secret key from a json secrets. If the key is not found, it will fallback to the list of paths provided

        :param fallbacks: list of paths to json files to fallback to
        :return: secret key
        """
        secret_key = self.get_secret(self.django_secret_key_name)
        if not self._validate_secret_key(secret_key):
            warnings.warn(f'DJSM: Invalid Key Found!')
            fallbacks = filter(lambda path_to_fallback_secret_key_file: bool(path_to_fallback_secret_key_file), self.secret_key_fallbacks)
            fallback_djsms = map(lambda path: DjangoJSONSecretManager(path), fallbacks)
            for fallback_djsm in fallback_djsms:
                print(f"DJSM: Searching for Fallbacks...")
                fallback_djsm.django_secret_key_name = self.django_secret_key_name
                secret_key = fallback_djsm.generate_secret_key()
                if secret_key:
                    break
        return secret_key if self._validate_secret_key(secret_key) else None


    @staticmethod
    def _validate_secret_key(secret_key: str):
        if not isinstance(secret_key, str):
            return False
        if len(secret_key) != 50:
            return False
        return True


# Pre-instantiate a DJSM object
djsm = DjangoJSONSecretManager(os.environ.get('SECRETS_FILE_PATH'))
if os.environ.get('DJANGO_SECRET_KEY_NAME', None):
    djsm.django_secret_key_name = os.environ.get('DJANGO_SECRET_KEY_NAME')
if os.environ.get('DJANGO_SECRET_KEY_FILE_PATH', None):
    djsm.django_secret_key_file_path = os.environ.get('DJANGO_SECRET_KEY_FILE_PATH')
djsm.secret_key_fallbacks = os.environ.get('DJANGO_SECRET_KEY_FALLBACKS_PATHS', '').split(',')