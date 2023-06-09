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

from .manager import DjangoJSONSecretManager as DJSM
from .manager import EnvLoadError, find_and_load_env_var, CryptKeysNotFound


find_and_load_env_var()

env_variables = [
    "SECRETS_FILE_PATH",
    "DJANGO_SECRET_KEY_NAME",
    "DJANGO_SECRET_KEY_FILE_PATH",
]

# Pre-instantiate a DJSM object
djsm = DJSM(os.environ.get('SECRETS_FILE_PATH'))

