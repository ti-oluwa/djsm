import string
from dotenv import load_dotenv, find_dotenv, dotenv_values

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


def check_setup_ok():
    """
    Check that an .env file is present and has been properly setup
    
    :return: True if setup is OK, False if not
    """
    setup_ok = True
    print("DJSM: Ensuring setup is OK\n")
    try:
        print("DJSM: Searching for .env file...\n")
        dotenv_path = find_dotenv(raise_error_if_not_found=True)
    except EnvLoadError:
        setup_ok = False
        print("DJSM: Could not load or find .env file!\n")
        return setup_ok

    print("DJSM: Checking that .env file has been properly setup...\n")
    env_file_dict = dotenv_values(dotenv_path)
    if not env_file_dict.get('DJSM_SECRETS_FILE_PATH', None):
        print('DJSM: DJSM_SECRETS_FILE_PATH not set in .env file\n')
        setup_ok = False
        
    if setup_ok:
        load_dotenv(dotenv_path, override=True)
        print('DJSM: Setup OK!\n')
    else:
        print('DJSM: Visit https://github.com/ti-oluwa/djsm/#usage for help on how to setup DJSM\n')
    return setup_ok
 
