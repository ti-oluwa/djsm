import string
from dotenv import load_dotenv, find_dotenv, dotenv_values
import sys
import random

from .exceptions import EnvLoadError


SECRET_KEY_ALLOWED_CHARS = string.ascii_letters + string.digits + string.punctuation

env_variables = (
    "DJSM_SECRETS_FILE_PATH",
    "DJSM_SECRET_KEY_NAME",
)


def find_and_load_env_var():
    """Load environment variables from .env file"""
    try:
        load_dotenv(find_dotenv('.env', raise_error_if_not_found=True), override=True)
    except Exception:
        raise EnvLoadError("Could not load environmental variables because '.env' file was not found. Create one!")
    return None


def _print(msg: str, quiet: bool = False):
    if not quiet:
        sys.stdout.write(msg)


def check_setup(quiet: bool = False):
    """
    Check that an .env file is present and has been properly setup
    
    :param quiet: If True, do not write anything to stdout (to avoid cluttering the console)
    :return: True if setup is OK, False if not
    """
    setup_ok = True
    _print("DJSM: Ensuring setup is OK.\n", quiet=quiet)
    try:
        _print("DJSM: Searching for .env file...\n", quiet=quiet)
        dotenv_path = find_dotenv(raise_error_if_not_found=True)
    except IOError:
        setup_ok = False
        _print("DJSM: Could not load or find .env file!\n")

    if setup_ok:
        _print("DJSM: Checking that .env file has been properly setup...\n", quiet=quiet)
        env_file_dict = dotenv_values(dotenv_path)
        if not env_file_dict.get('DJSM_SECRETS_FILE_PATH', None):
            _print('DJSM: DJSM_SECRETS_FILE_PATH not set in .env file\n')
            setup_ok = False
        
    if setup_ok:
        load_dotenv(dotenv_path, override=True)
        _print('DJSM: Setup OK!\n', quiet=quiet)
    else:
        _print('DJSM: Visit https://github.com/ti-oluwa/djsm/#usage for help on how to setup DJSM\n')
    return setup_ok
 

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


def generate_django_secret_key(length: int = 50):
    """
    Return a randomly generated key of not less than 32 characters
    
    :param length: length of secret key to be generated.
    """
    if length < 32:
        raise ValueError('Secret key length cannot be less than 32 characters')
    return ''.join(random.choice(SECRET_KEY_ALLOWED_CHARS) for _ in range(length))
