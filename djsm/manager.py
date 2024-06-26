from typing import Any, Dict
import os
import simple_file_handler as sfh
from dotenv import find_dotenv, dotenv_values
import dcrypt

from .exceptions import CryptKeysNotFound
from .misc import (
    _print, env_variables, find_and_load_env_var, 
    generate_django_secret_key, validate_secret_key
)


def _get_env_hdl():
    """Returns an `FileHandler` object for an .env file"""
    return sfh.FileHandler(find_dotenv(raise_error_if_not_found=True), allow_any=True) 



class DjangoJSONSecretManager:
    cryptkeys_filename = 'cryptkeys.json'
    """The default name in which the manager's cryptkeys will be stored"""

    def __init__(self, path_to_secret_file: str, *, quiet: bool = False) -> None:
        """
        Creates a new DjangoJSONSecretManager object.

        :param path_to_secret_file: path the file where secrets are stored or secrets will be stored.
        :param quiet: If True, do not write anything to stdout (to avoid cluttering the console)
        """
        try:
            path = os.path.normpath(path_to_secret_file)
        except Exception:
            raise ValueError('`path_to_secret_file` must be a valid path')
        if not path.endswith('.json'):
            raise ValueError(
                'Secret file must be a json file'
            )
        self.secrets_file_path = path
        self.stdout = lambda msg: _print(msg, quiet=quiet)
        
        dj_keyname = os.getenv('DJSM_SECRET_KEY_NAME')
        if dj_keyname:
            if not isinstance(dj_keyname, str):
                raise TypeError('DJSM_SECRET_KEY_NAME must be a string')
            if not dj_keyname.isidentifier():
                raise ValueError('DJSM_SECRET_KEY_NAME must be a valid identifier')
            self.secret_key_name = dj_keyname
        else:
            self.secret_key_name = 'django_secret_key'
        return None

    @property
    def cryptkeys_filepath(self) -> str:
        """Returns the path to the crypt keys file"""
        return f"{os.path.dirname(self.secrets_file_path)}\\{self.cryptkeys_filename.split('.')[0]}.json"
    

    def __setattr__(self, __name: str, __value: Any) -> None:
        if "path" in __name:
            if not os.path.isabs(__value):
                __value = os.path.abspath(__value)
        return super().__setattr__(__name, __value)


    def _encrypt(self, secret: Dict) -> Dict:
        """
        Encrypts a secret using the encryption key.

        :param secret: secret to be encrypted
        :return: encrypted secret
        """
        if not isinstance(secret, dict):
            raise TypeError("secret must be a dict")
        
        with sfh.FileHandler(self.cryptkeys_filepath) as crypt_keys_file_hdl:
            try:
                cryptkeys: Dict = crypt_keys_file_hdl.read_file()
                m_key = cryptkeys.get('DJSM_MASTER_KEY', None)
                pub_key = cryptkeys.get('DJSM_PUBLIC_KEY', None)
            except Exception:
                m_key, pub_key = None, None
            priv_key = os.getenv('DJSM_PRIVATE_KEY')

            if all((m_key, pub_key, priv_key)) is False:
                key_signature = dcrypt.CryptKey.make_signature(hash_algorithm="SHA-256")
                m_key, pub_key, priv_key, _ = key_signature.common()
                cryptkeys = {
                    'DJSM_MASTER_KEY': m_key,
                    'DJSM_PUBLIC_KEY': pub_key,
                }
                crypt_keys_file_hdl.write_to_file(cryptkeys)
                del cryptkeys
                self._remove_priv_key_from_env()
                env_file_hdl = _get_env_hdl()
                env_file_hdl.write_to_file(f'DJSM_PRIVATE_KEY = "{priv_key}"\n', write_mode='a+')
                self.reload_env()

            common_signature = dcrypt.CommonSignature(m_key, pub_key, priv_key, "SHA-256")
            cryptkey = dcrypt.CryptKey(signature=dcrypt.Signature.from_common(common_signature))
            crypt = dcrypt.JSONCrypt(key=cryptkey)
            del m_key, pub_key, priv_key
            return crypt.encrypt(secret)


    def _decrypt(self, encrypted_secret: Dict) -> Dict:
        """
        Decrypts an encrypted secret using the encryption key.

        :param encrypted_secret: encrypted secret to be decrypted
        :return: decrypted secret
        """
        if not isinstance(encrypted_secret, dict):
            raise TypeError("encrypted_secret must be a dict")
        
        with sfh.FileHandler(self.cryptkeys_filepath) as crypt_keys_file_hdl:
            try:
                cryptkeys: Dict = crypt_keys_file_hdl.read_file()
                m_key: str = cryptkeys.get('DJSM_MASTER_KEY', None)
                pub_key: str = cryptkeys.get('DJSM_PUBLIC_KEY', None)
            except Exception:
                m_key, pub_key = None, None

            priv_key: str = os.getenv('DJSM_PRIVATE_KEY')

            if all((m_key, pub_key, priv_key)) is False:
                raise CryptKeysNotFound("Crypt key(s) not found. Secrets will not be recoverable")

            common_signature = dcrypt.CommonSignature(m_key, pub_key, priv_key, "SHA-256")
            cryptkey = dcrypt.CryptKey(signature=dcrypt.Signature.from_common(common_signature))
            crypt = dcrypt.JSONCrypt(key=cryptkey)
            del m_key, pub_key, priv_key
            return crypt.decrypt(encrypted_secret)
    

    @staticmethod
    def _remove_priv_key_from_env() -> None:
        """Removes rsa private key from .env file and environmental variables if present"""
        with _get_env_hdl() as env_file_handler:
            env_file_dict = dotenv_values(find_dotenv(raise_error_if_not_found=True))
            env_file_dict.pop('DJSM_PRIVATE_KEY', None)

            # Clear existing variables in .env file and re-write
            env_file_handler.clear_file()
            for key, value in env_file_dict.items():
                line = f'{key} = "{value}"\n'
                env_file_handler.write_to_file(line, write_mode='a+')
            os.environ.pop("DJSM_PRIVATE_KEY", None)
        return None


    def change_cryptkeys(self) -> None:
        """
        Change the encryption keys
        """
        # Get existing secrets
        secrets = self._load_secrets(self.secrets_file_path, decrypt=True)
        # Delete fernet and rsa public keys in JSON file - Just delete the cryptkeys file
        sfh.FileHandler(self.cryptkeys_filepath).delete_file()
        # Delete rsa private key in .env file
        self._remove_priv_key_from_env()
        # Re-write secrets (overwrite) while encrypting them with new keys
        self._write_secrets(secrets, self.secrets_file_path, encrypt=True, overwrite=True)
        del secrets
        return None
        

    def get_or_create_secret_key(self, always_generate: bool = False) -> str:
        """
        Gets Django secret key from secrets file, if it exists.
        Create and saves a secret key in secrets file if it cannot be found.

        The secret key will be saved to the path specified in the constructor or as specified in the
        .env file

        :param always_generate: if True, a new secret key will be generated and saved
        even if one already exists in the secret file.
        :return: secret key
        """ 
        secret_key = self.get_secret(self.secret_key_name)
        if not secret_key or always_generate:
            self.stdout("DJSM: Generating Secret Key...\n")
            secret_key = generate_django_secret_key()
            self.update_secrets({self.secret_key_name: secret_key})
            self.stdout("DJSM: Secret Key Generated Successfully!\n")
        else:
            self.stdout("DJSM: Secret Key Found!\n")

        if not validate_secret_key(secret_key):
            self.stdout("DJSM: Invalid Secret Key. Replacing Key...\n")
            # Replace secret key if the secret key is not valid and return the new secret key
            return self.get_or_create_secret_key(always_generate=True)
        return secret_key


    def _write_secrets(
        self, 
        secrets: Dict[str, Any], 
        path_to_file: str, 
        overwrite: bool = False, 
        encrypt: bool = False
    ) -> None:
        """
        Writes the secrets in the given path.

        :param secrets: dictionary containing new secrets.
        :param path_to_file: path to file in which secrets will be written into.
        :param overwrite: whether to overwrite all existing secrets in the file.
        :param encrypt: whether to encrypt the secrets before writing in the file. 
        :return: None.
        """
        if not isinstance(secrets, dict):
            raise TypeError('Secret must be a dictionary')

        with sfh.FileHandler(path_to_file) as file_hdl:
            if not file_hdl.filetype == "json":
                raise TypeError("Secret file must be a json file")

            if secrets:
                if encrypt:
                    secrets = self._encrypt(secrets)
                if overwrite:
                    file_hdl.write_to_file(secrets)
                else:
                    file_hdl.update_json(secrets)
                del secrets
        return None

    
    def _load_secrets(self, path_to_file: str, decrypt: bool = False) -> Dict:
        """
        Loads the secrets from the given path.

        :param path_to_file: path to file containing secrets.
        :param decrypt: whether to decrypt the secrets in the file before returning.
        :return: a dictionary of secrets.
        """
        with sfh.FileHandler(path_to_file) as file_hdl:
            try:
                if not file_hdl.filetype == "json":
                    raise TypeError("Secret file must be a json file")

                enc_secrets = file_hdl.read_file()
                if not isinstance(enc_secrets, dict):
                    raise TypeError('Secrets must be a dictionary')
                if enc_secrets and decrypt:
                    return self._decrypt(enc_secrets)
                return enc_secrets
            
            except sfh.FileError:
                return {}


    def get_secret(self, key: str) -> Any | None:
        """
        Gets secret from json secret(s) file.

        :param key: key to get from the json file(s)
        :return: secret if found, None if not
        """ 
        enc_secrets = self._load_secrets(self.secrets_file_path)
        enc_secret = enc_secrets.get(key, None)
        if enc_secret:
            dec_secret = self._decrypt({key: enc_secret})
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
        self._write_secrets(new_secrets, self.secrets_file_path, encrypt=True)
        del new_secrets
        return None


    def clean_up(self) -> None:
        """
        Deletes all secrets in the secrets file. Clears all environment variables
        set by the package.

        This method is useful when you want to delete all secrets and start afresh.
        The cryptkeys are left untouched.
        """
        sfh.FileHandler(self.secrets_file_path).delete_file()
        for var in env_variables:
            os.environ.pop(var, None)
        return None


    @staticmethod
    def reload_env() -> None:
        """
        Reloads the environment variables from the .env file.
        """
        find_and_load_env_var()
        return None


    def clean_up_and_reload(self) -> None:
        """
        Deletes all secrets in the secret file. Clears all environment variables
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

