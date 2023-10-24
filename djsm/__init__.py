"""
----------------------------------
djsm - Django JSON Secrets Manager
----------------------------------
djsm helps create, store, retrieve, update and manage secrets in Django

LICENSE: GPLv3
"""

__version__ = "0.1.1"
__author__ = "Daniel T. Afolayan (ti-oluwa)"
__license__ = "MIT"

import os
import sys

from .manager import DJSM
from .misc import check_setup_ok

__djsm_setup_checked = False

def get_djsm():
    """
    Returns an instance of the DJSM class instantiated based on the environment variables set.
    """
    global __djsm_setup_checked
    if not __djsm_setup_checked:
        if not check_setup_ok():
            sys.exit()
        __djsm_setup_checked = True
    return DJSM(os.getenv('DJSM_SECRETS_FILE_PATH'))


