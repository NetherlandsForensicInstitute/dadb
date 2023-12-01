''' __init__.py - module initialization for DADB

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

import platform as _platform
import sys as _sys

# only Linux is supported
_my_os = _platform.system()
if _my_os != 'Linux':
    from ._exceptions import OnlySupportedOnLinuxError
    raise OnlySupportedOnLinuxError("DADB only works on Linux systems")

# DADB API
from ._common import version
from ._common import progresswrapper
from ._common import APIVERSION
from ._schema import SCHEMAVERSION
from ._database import Database
from ._data import Data
from ._model_definition import model_definition
from ._model_definition import field_definition
from . import _exceptions as exceptions

# built-in models
from .models import filemodel
from .models import fileparentmodel
from .models import filesetmodel
from .models import libmagicmodel
from .models import archivemodel
from .models import decompressmodel
from .models import stringsmodel


def register_all_models(db):
    ''' register all available models with the given database '''

    filemodel.register_with_db(db)
    fileparentmodel.register_with_db(db)
    filesetmodel.register_with_db(db)
    libmagicmodel.register_with_db(db)
    archivemodel.register_with_db(db)
    decompressmodel.register_with_db(db)
    stringsmodel.register_with_db(db)
