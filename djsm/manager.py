from typing import Any, Dict
import os
from bs4_web_scraper.file_handler import FileHandler
import bs4_web_scraper
from dotenv import find_dotenv, dotenv_values
import random

from .jcrypt import JSONCrypt as JCrypt
from .exceptions import CryptKeysNotFound
from .misc import SECRET_KEY_ALLOWED_CHARS, env_variables, find_and_load_env_var


class DjangoJSONSecretManager:
    
    secret_key_name: str = 'djangosecretkey'
    cryptkeys_filename: str = 'cryptkeys.json'

    def __init__(self, path_to_secret_file: str):
        """
        Initialize the class.

        :param path_to_secret_file: path the file where secrets are stored or secrets will be stored.
        """
        try:
            path = os.path.normpath(path_to_secret_file)
        except Exception:
            raise ValueError('`path_to_secret_file` must be a valid path')
        if not path.endswith('.json'):
            raise ValueError('Secret file must be a json file')
        self.secrets_file_path = path

        dj_keyname = os.getenv('DJSM_SECRET_KEY_NAME')
        if dj_keyname:
            if not isinstance(dj_keyname, str):
                raise TypeError('DJSM_SECRET_KEY_NAME must be a string')
            if not dj_keyname.isidentifier():
                raise ValueError('DJSM_SECRET_KEY_NAME must be a valid identifier')
            self.secret_key_name = dj_keyname


    @property
    def cryptkeys_filepath(self):
        """Returns the path to the crypt keys file"""
        return f"{os.path.dirname(self.secrets_file_path)}\{self.cryptkeys_filename.split('.')[0]}.json"
    

    def __setattr__(self, __name: str, __value: Any) -> None:
        if "path" in __name:
            if not os.path.isabs(__value):
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
        
        crypt_keys_file_hdl = FileHandler(self.cryptkeys_filepath)
        try:
            crypt_keys: Dict = crypt_keys_file_hdl.read_file()
            f_key = crypt_keys.get('DJSM_FERNET_KEY', None)
            pub_key = crypt_keys.get('DJSM_RSA_PUBLIC_KEY', None)
        except:
            f_key, pub_key = None, None
        priv_key = os.getenv('DJSM_RSA_PRIVATE_KEY')

        try:
            if all((f_key, pub_key, priv_key)) == False:
                f_key, pub_key, priv_key = JCrypt.generate_keys_as_str()
                crypt_keys = {
                    'DJSM_FERNET_KEY': f_key,
                    'DJSM_RSA_PUBLIC_KEY': pub_key,
                }
                crypt_keys_file_hdl.write_to_file(crypt_keys)
                del crypt_keys
                self._remove_rsa_priv_key_from_env()
                env_file_hdl = self._get_env_hdl()
                try:
                    env_file_hdl.write_to_file(f'DJSM_RSA_PRIVATE_KEY = "{priv_key}"\n', write_mode='a+')
                except Exception as exc:
                    raise exc
                finally:
                    env_file_hdl.close_file()
                self.reload_env()
        except Exception as exc:
            raise exc
        finally:
            crypt_keys_file_hdl.close_file()

        jcrypt = JCrypt.from_str(f_key, pub_key, priv_key)
        del f_key, pub_key, priv_key
        encrypted_secret = jcrypt.encrypt(secret)
        return encrypted_secret


    def decrypt(self, encrypted_secret: Dict) -> Dict:
        """
        Decrypts an encrypted secret using the encryption key.

        :param encrypted_secret: encrypted secret to be decrypted
        :return: decrypted secret
        """
        if not isinstance(encrypted_secret, dict):
            raise TypeError("encrypted_secret must be a dict")
        
        try:
            crypt_keys_file_hdl = FileHandler(self.cryptkeys_filepath)
            crypt_keys: Dict = crypt_keys_file_hdl.read_file()
            f_key = crypt_keys.get('DJSM_FERNET_KEY', None)
            pub_key = crypt_keys.get('DJSM_RSA_PUBLIC_KEY', None)
        except:
            f_key, pub_key = None, None
        finally:
            crypt_keys_file_hdl.close_file()
        priv_key = os.getenv('DJSM_RSA_PRIVATE_KEY')

        if all((f_key, pub_key, priv_key)) == False:
            raise CryptKeysNotFound("Crypt key(s) not found. Secrets will not be recoverable")

        jcrypt = JCrypt.from_str(f_key, pub_key, priv_key)
        del f_key, pub_key, priv_key
        decrypted_secret = jcrypt.decrypt(encrypted_secret)
        return decrypted_secret


    @staticmethod
    def _get_env_hdl():
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


    def _remove_rsa_priv_key_from_env(self):
        """Removes rsa private key from .env file and environmental variables if present"""
        env_file_handler = self._get_env_hdl()
        try:
            env_file_dict = dotenv_values(find_dotenv(raise_error_if_not_found=True))
            env_file_dict.pop('DJSM_RSA_PRIVATE_KEY', None)

            # Clear existing variables in .env file and re-write
            env_file_handler.clear_file()
            for key, value in env_file_dict.items():
                line = f'{key} = "{value}"\n'
                env_file_handler.write_to_file(line, write_mode='a+')
            os.environ.pop("DJSM_RSA_PRIVATE_KEY", None)
        except Exception as exc:
            raise exc
        finally:
            env_file_handler.close_file()
        return None


    def change_crypt_keys(self):
        """
        Change the encryption keys
        """
        # Get existing secrets
        secrets = self.load_secrets(self.secrets_file_path, decrypt=True)
        # Delete fernet and rsa public keys in JSON file - Just delete the cryptkeys file
        FileHandler(self.cryptkeys_filepath).delete_file()
        # Delete rsa private key in .env file
        self._remove_rsa_priv_key_from_env()
        # Re-write secrets (overwrite) while encrypting them with new keys
        self.write_secrets(secrets, self.secrets_file_path, encrypt=True, overwrite=True)
        del secrets
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
        secret_key = self.get_secret(self.secret_key_name)
        if not secret_key or always_generate:
            print("DJSM: Generating Secret Key...\n")
            secret_key = self.generate_django_secret_key()
            self.update_secrets({self.secret_key_name: secret_key})
            print("DJSM: Secret Key Generated Successfully\n")
        else:
            print("DJSM: Secret Key Found\n")
        if not self.validate_secret_key(secret_key):
            print("DJSM: Invalid Secret Key. Replacing Key...\n")
            # Replace secret key if the secret key is not valid and return the new secret key
            return self.change_secret_key()
        return secret_key


    def change_secret_key(self):
        """
        Replaces Django secret key with a new one.

        :return: new secret key
        """
        return self.get_or_create_secret_key(always_generate=True)


    def write_secrets(
            self, 
            secrets: Dict[str, Any], 
            path_to_file: str, 
            overwrite: bool = False, 
            encrypt: bool = False
        ) -> None:
        """
        Writes the secrets in the given path.

        :param secrets: secrets to be written.
        :param path_to_file: path to file in which secrets will be written.
        :param overwrite: whether to overwrite the secrets in the file.
        :param encrypt: whether to encrypt the secrets before writing in the file. 
        :return: None.
        """
        if not isinstance(secrets, dict):
            raise TypeError('Secret must be a dictionary')

        try:
            file_hdl = FileHandler(path_to_file)
            if not file_hdl.filetype == "json":
                raise TypeError("Secret file must be a json file")

            if secrets:
                if encrypt:
                    secrets = self.encrypt(secrets)
                if overwrite:
                    file_hdl.write_to_file(secrets)
                else:
                    file_hdl.update_json(secrets)
                del secrets
        except Exception as exc:
            raise exc
        finally:
            file_hdl.close_file()
        return None

    
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

            enc_secrets = file_hdl.read_file()
            if not isinstance(enc_secrets, dict):
                raise TypeError('Secrets must be a dictionary')
            if enc_secrets and decrypt:
                return self.decrypt(enc_secrets)
            return enc_secrets
        except bs4_web_scraper.FileError:
            return {}
        except Exception as exc:
            raise exc
        finally:
            file_hdl.close_file()


    def get_secret(self, key: str) -> Any | None:
        """
        Gets secret from json secret(s) file.

        :param key: key to get from the json file(s)
        :return: secret if found, None if not
        """ 
        enc_secrets = self.load_secrets(self.secrets_file_path)
        enc_secret = enc_secrets.get(key, None)
        if enc_secret:
            dec_secret = self.decrypt({key: enc_secret})
            return dec_secret.get(key, None)
        return enc_secret


    def update_secrets(self, new_secrets: Dict[str, Any]) -> None:
        """
        Updates secrets in secrets file.

        :param new_secrets: secret to write to the json file
        :return: None
        """
        if not isinstance(new_secrets, dict):
            raise TypeError('Secret must be a dictionary')
        self.write_secrets(new_secrets, self.secrets_file_path, encrypt=True)
        del new_secrets
        return None


    def clean_up(self):
        """
        Deletes all secrets in the secrets file. Removes all environment variables
        set by the package.

        This method is useful when you want to delete all secrets and start afresh.
        Crypt keys are left untouched.
        """
        FileHandler(self.secrets_file_path).delete_file()
        self._remove_rsa_priv_key_from_env()
        for var in env_variables:
            os.environ.pop(var, None)
        return None


    def reload_env(self):
        """
        Reloads the environment variables from the .env file.
        """
        find_and_load_env_var()
        return None


    def clean_up_and_reload(self):
        """
        Deletes all secrets in the json secrets, and secret key files. Removes all environment variables
        set by the package and reloads the environment variables from the .env file.

        This method is useful when you want to delete all secrets and start afresh.
        """
        self.clean_up()
        self.reload_env()
        return None


# Just to allow use of alias "DJSM"
class DJSM(DjangoJSONSecretManager):
    """
    #### DJSM class for managing Django secrets in a json file.

    EXAMPLE:

    In settings.py:
    ```
    from djsm import DJSM

    djsm = DJSM('./.hidden_folder/secretfile.json')
    # SECURITY WARNING: keep the secret key used in production secret!
        # generate secret key if it does not exist
    SECRET_KEY = djsm.get_or_create_secret_key()
    ```
    """
    pass

