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

env_variables = [
    "SECRETS_FILE_PATH",
    "SECRETS_FILE_FALLBACKS_PATHS",
    "DJANGO_SECRET_KEY_NAME",
    "DJANGO_SECRET_KEY_FILE_PATH",
    "DJANGO_SECRET_KEY_FALLBACKS_PATHS"
]

# Pre-instantiate a DJSM object
djsm = DJSM(os.environ.get('SECRETS_FILE_PATH'))
if os.environ.get('DJANGO_SECRET_KEY_NAME', None):
    djsm.django_secret_key_name = os.environ.get('DJANGO_SECRET_KEY_NAME')
if os.environ.get('DJANGO_SECRET_KEY_FILE_PATH', None):
    djsm.django_secret_key_file_path = os.environ.get('DJANGO_SECRET_KEY_FILE_PATH')
djsm.secret_key_fallbacks = os.environ.get('DJANGO_SECRET_KEY_FALLBACKS_PATHS', '').split(',')


