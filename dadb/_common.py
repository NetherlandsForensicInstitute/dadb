''' _common.py - common functions for DADB

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

# global imports
import os.path as _path


################################
### configuration parameters ###
################################

# increment this version when API-breaking things are changed in dadb,
# and add comment on reason for the change here:
#
# CHANGELOG:
#
# 1 -  initial version of API
# 2 -  fields are now in defined order and no longer sorted by name
# 3 -  removed all support for non-uniform fields
#
APIVERSION=3

# We use a prefix to prevent table names from being "english" words or
# from accidentally colliding with SQLite keywords. Each table or field
# name is prefixed with this prefix
DBPREFIX = 'x'
# We can use an additional prefix for table names
TABLEPREFIX = ''
# And we use a prefix for fields.
# This is mandatory non-blank to prevent name_clashes with the pkey field
FIELDPREFIX = '_'


########################
### common functions ###
########################


def version():
    ''' return the version of DADB '''

    _modulepath = _path.abspath(__file__)
    _moduledir = _path.split(_modulepath)[0]
    _versionfile = _path.join(_moduledir, 'VERSION')
    with open(_versionfile, 'rt') as f:
        version = f.readline()
        return version


def progresswrapper(sequence, desc=None, unit='rec'):
    ''' a simple wrapper that prints a progressbar on iteration (if you have tqdm)

    Arguments:
    - sequence:   the list or iterator
    - desc:       an optional string to print before progressbar

    Returnvalue:
    - sequence:   the wrapped sequence

    You need the tqdm module in order to make this work. If you don't have it
    the situation will be handled gracefully.
    '''

    try:
        from tqdm import tqdm as _tqdm
    except:
        # we don't have tqdm, return sequence without wrapping in tqdm sequence
        return sequence

    # if we have a generator, convert to list to know number of iterations
    sequence = list(sequence)
    sequence = _tqdm(sequence, desc=desc, unit=' {:s}'.format(unit),
                     leave=True, ncols=80)
    return sequence
