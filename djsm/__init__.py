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
from dotenv import load_dotenv, find_dotenv

from .manager import DjangoJSONSecretManager as DJSM
from .manager import EnvLoadError

# load environment variables from .env file
try:
    load_dotenv(find_dotenv('.env', raise_error_if_not_found=True), override=True)
except Exception as e:
    raise EnvLoadError("Could not load environmental variables because '.env' file was not found. Create one!")

env_variables = [
    "SECRETS_FILE_PATH",
    "DJANGO_SECRET_KEY_NAME",
    "DJANGO_SECRET_KEY_FILE_PATH",
]

# Pre-instantiate a DJSM object
djsm = DJSM(os.environ.get('SECRETS_FILE_PATH'))

