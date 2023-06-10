"""
----------------------------------
djsm - Django JSON Secrets Manager
==================================
djsm helps create, store, retrieve, update and manage secrets in Django

LICENSE: MIT
"""

__version__ = "0.0.1"
__author__ = "ti-oluwa"
__license__ = "MIT"

import os
import sys

from .manager import DjangoJSONSecretManager as DJSM
from .manager import EnvLoadError, find_and_load_env_var, CryptKeysNotFound, check_setup_ok

__setup_ok = check_setup_ok()
if not __setup_ok:
    sys.exit()

env_variables = [
    "SECRETS_FILE_PATH",
    "DJANGO_SECRET_KEY_NAME",
    "DJANGO_SECRET_KEY_FILE_PATH",
]

# Pre-instantiate a DJSM object
djsm = DJSM(os.getenv('SECRETS_FILE_PATH'))

