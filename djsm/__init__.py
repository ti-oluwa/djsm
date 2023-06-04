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

from .manager import DjangoJSONSecretManager as DJSM

env_variables = [
    "SECRETS_FILE_PATH",
    "SECRETS_FILE_FALLBACKS_PATHS",
    "DJANGO_SECRET_KEY_NAME",
    "DJANGO_SECRET_KEY_FILE_PATH",
    "DJANGO_SECRET_KEY_FALLBACKS_PATHS"
]


