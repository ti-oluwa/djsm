"""
----------------------------------
djsm - Django JSON Secrets Manager
==================================
djsm helps create, store, retrieve, update and manage secrets in Django

LICENSE: MIT
"""

__version__ = "0.1.0"
__author__ = "Daniel T. Afolayan (ti-oluwa)"
__license__ = "MIT"

import os
import sys

from .manager import DjangoJSONSecretManager as DJSM
from .manager import check_setup_ok

_setup_checked = False

def _check_setup():
    global _setup_checked
    if not _setup_checked:
        if not check_setup_ok():
            sys.exit()
        _setup_checked = True
    return None

_check_setup()

# Pre-instantiate a DJSM object
djsm = DJSM(os.getenv('DJSM_SECRETS_FILE_PATH'))

