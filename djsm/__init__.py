"""
#### djsm - Django JSON Secrets Manager

Create, store, retrieve, update and manage secrets in your Django project.

@Author: Daniel T. Afolayan (ti-oluwa.github.io)
"""

__version__ = "0.1.3"
__author__ = "Daniel T. Afolayan (ti-oluwa)"
__license__ = "GPLv3"

import os
import sys

from .manager import DJSM
from .misc import check_setup

_djsm_setup_checked = False


def get_djsm(quiet: bool = False):
    """
    Returns an instance of the DJSM class instantiated based on the environment variables set.

    :param quiet: If True, do not write anything to stdout (to avoid cluttering the console)
    """
    global _djsm_setup_checked
    if not _djsm_setup_checked:
        if not check_setup(quiet):
            sys.exit()
        _djsm_setup_checked = True
    return DJSM(os.getenv('DJSM_SECRETS_FILE_PATH'), quiet=quiet)


