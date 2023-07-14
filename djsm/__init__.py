"""
----------------------------------
djsm - Django JSON Secrets Manager
==================================
djsm helps create, store, retrieve, update and manage secrets in Django

LICENSE: MIT
"""

__version__ = "0.0.4"
__author__ = "Daniel T. Afolayan (ti-oluwa)"
__license__ = "MIT"

import os
import sys

from .manager import DjangoJSONSecretManager as DJSM
from .manager import (EnvLoadError, find_and_load_env_var, CryptKeysNotFound, check_setup_ok, env_variables)

__setup_ok = check_setup_ok()
if not __setup_ok:
    sys.exit()

# Pre-instantiate a DJSM object
djsm = DJSM(os.getenv('DJSM_SECRETS_FILE_PATH'))

