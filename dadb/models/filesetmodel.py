''' fileset_model - model for defining a group of files in DADB

Copyright (c) 2023 Netherlands Forensic Institute - MIT License

Conceptually, a fileset is merely an ordered list of file items.

A fileset is defined in such a way that it can include the same file item
multiple times in different locations in the list of files. If the label
and the sequence of files is exactly the same, this is considered a
duplicate fileset. If the label is the same, but the group of files is
different, this is considered to be a distinct fileset (label is not
unique). If the label is the same, and the group of files is the same, but
just in a different order, this is considered to be a distinct fileset.

In other words, each unique combination of files with a unique label is
considered a unique fileset. This allows for a flexible use of the fileset
model for various purposes (i.e. for defining archives, or groups of files
that together make up an application or a firmware). If unique labels are
important to the user of this model, the user has to take care of this.
'''

import os as _os

from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import exceptions as _exceptions
from .. import progresswrapper as _progresswrapper

from . import filemodel as _filemodel
from . import fileparentmodel as _fparentmodel

##########
# MODELS #
##########

# changelog
# 1 - initial version

MODELNAME = 'fileset'
MODELDESCRIPTION = 'file set model for DADB'
MODELVERSION = 1

modeldef = _model_def(MODELNAME,
                      [_field_def('label', str, nullable=False),
                       _field_def('files', (_filemodel.modeldef,), nullable=False)],
                      MODELDESCRIPTION, MODELVERSION,
                      # we can have multiple filesets consisting of the same
                      # set of files, as long as their label differs
                      implicit_dedup=True, explicit_dedup=True)

#######
# API #
#######


class FilesetError(Exception):
    ''' raised when an error occurs during insertion of a fileset '''

    pass


def register_with_db(db):
    ''' register the model to the database '''

    _filemodel.register_with_db(db)
    _fparentmodel.register_with_db(db)
    db.register_model(modeldef)


def insert(db, label, fileset, progress=False):
    ''' insert a fileset, consisting of one or more files

    Arguments:
    - label     : a free-form string identifying the fileset
    - fileset   : the files making up this fileset, defined in one of 6 ways:

    1) a single file modelitem, as inserted earlier into the database
    2) a single integer, indicating the id of the file in this fileset
    3) the path of a single file on the local filesystem
    4) a tuple of file modelitems, as inserted earlier into the database
    5) a tuple of integers, indicating the ids of the files in this fileset
    6) the path of a directory (or symlink to directory) on the local filesystem

    The fileset may contain duplicate files, and the order of the files matters
    (i.e. if a fileset has the same label, but the order of the files differs,
    it is considered to be a different fileset). This allows for a flexible use
    of the fileset model for various purposes (i.e. in defining archives or
    groups of files that make up an application or a firmware)
    '''

    db.check_registered(MODELNAME)
    db.check_registered(_filemodel.MODELNAME)

    # check if fileset by that label already exists
    existing = get_by_label(db, label)
    if existing is not None:
        raise ValueError('A fileset with that label already exists')

    # we want to make sure all of it happens, or nothing at all!
    started_transaction = db.begin_transaction()

    files = []
    was_dir_import = False

    if isinstance(fileset, str):
        # case 3 or 6, the fileset is a string
        fileset = _os.path.abspath(_os.path.expanduser(fileset))

        # check if path exists, abort if not
        if not _os.path.exists(fileset):
            if started_transaction is True:
                db.rollback_transaction()
            raise FilesetError('given path does not exist')

        if _os.path.isdir(fileset):
            # case 6: we are dealing with a directory, insert files
            #         recursively, starting with root dir
            was_dir_import = True
            file_walker = _walker(fileset)
            if progress is True:
                file_walker = _progresswrapper(file_walker, '{:20s}'.format('    fileset'))
            for fname in file_walker:
                try:
                    rowid = _file_inserter(db, fname)
                except:
                    if started_transaction is True:
                        db.rollback_transaction()
                    raise
                files.append(rowid)

        elif _os.path.isfile(fileset) or _os.path.islink(fileset):
            # case 3: we are dealing with a single filename
            try:
                rowid = _file_inserter(db, fileset)
            except:
                if started_transaction is True:
                    db.rollback_transaction()
                raise
            files.append(rowid)

        else:
            if started_transaction is True:
                db.rollback_transactin()
            raise FilesetError('could not insert fileset')

    elif isinstance(fileset, int):
        # case 2: we are dealing with a single file id, get the file
        #         and add to set (inserter function checks if id exists)
        files.append(fileset)

    elif db.isinstance(fileset, _filemodel.MODELNAME):
        # case 1: we are dealing with a single file modelitem, implicit insert
        files = (fileset,)

    elif isinstance(fileset, tuple):
        # case 4 or 5, check if all items are the same type
        types = set([type(f) for f in fileset])
        if len(types) != 1:
            if started_transaction is True:
                db.rollback_transaction()
            raise FilesetError('fileset tuple must contain same type of items')

        if db.isinstance(fileset[0], _filemodel.MODELNAME):
            # case 4: we are dealing with a sequence of file items,
            #         insert implicitly
            files = fileset

        elif isinstance(fileset[0], int):
            # case 5: we are dealing with a sequence of integers, assume these
            #         are all file ids (checked by inserter function)
            files = fileset

        else:
            if started_transaction is True:
                db.rollback_transaction()
            raise FilesetError('fileset tuple must contain integers or file items')

    else:
        if started_transaction is True:
            db.rollback_transaction()
        raise FilesetError('check fileset argument')

    # now that we have collected (and optionally inserted) the file items,
    # create and insert the fileset model item as well

    try:
        m = db.make_modelitem(MODELNAME, label=label, files=tuple(files))
        rowid = db.insert_modelitem(m)
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    # if this was a directory tree import, we can store the file
    # hierarchy via the fileparent model
    if was_dir_import is True:
        try:
            # we still have the sequence of rowids of the files
            _fparentmodel.insert_files(db, files, progress=progress)
        except:
            if started_transaction is True:
                db.rollback_transaction()
            raise

    if started_transaction is True:
        db.end_transaction()

    return rowid


def get(db, object_id):
    ''' returns the modelitem by its object_id '''

    try:
        return db.modelitem(MODELNAME, object_id)
    except _exceptions.NoSuchModelItemError:
        return None


def get_by_label(db, label, with_pkey=False):
    ''' return a fileset object by its label '''

    # we use direct query, so check model existence
    db.check_registered(MODELNAME)

    q = _label_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (label,))
    r = list(c)
    if len(r) == 0:
        return None
    elif len(r) != 1:
        raise ValueError('More than 1 fileset by that name')

    if with_pkey == True:
        return (r[0][0], db.modelitem(MODELNAME, r[0][0]))
    else:
        return db.modelitem(MODELNAME, r[0][0])


def get_filesets_with_file(db, file_, with_pkey=False):
    ''' yield filesets with the given file in it '''

    if isinstance(file_, int):
        fileid = file_
    elif db.isinstance(file_, _filemodel.MODELNAME):
        fileid = db.modelitem_id(file_)
    else:
        raise FilesetError("provide file id or file object")

    # we use direct query, so check model existence
    db.check_registered(MODELNAME)

    q = _file_id_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (fileid,))
    # exhaust the cursor to prevent problems
    results = list(c)

    if with_pkey == True:
        results = [(r[0], db.modelitem(MODELNAME, r[0])) for r in results]
    else:
        results = [db.modelitem(MODELNAME, r[0]) for r in results]

    for r in results:
        yield r


def items(db, with_pkey=False):
    ''' yield modelitems '''

    return db.modelitems(MODELNAME, with_pkey)


####################
# helper functions #
####################


def _file_inserter(db, filename):
    ''' insert file, dealing with ExplicitDuplicateException appropriately '''

    try:
        rowid = _filemodel.insert(db, filename)
    except _exceptions.ExplicitDuplicateError as e:
        # get the rowid of the existing item by parsing the error message (yuk!)
        orig_id = int(e.args[0].split('with id ')[1].split(', explicit insert')[0])
        # check by fetching the original item
        orig_item = _filemodel.get(db, orig_id)
        if orig_item.path != filename:
            raise
        return orig_id
    return rowid


def _label_query(db):
    ''' constructs (or fetches from cache) partial query to get fileset by label '''

    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    labelcol = db.get_colname(MODELNAME, 'label')
    q = '''SELECT {:s}
           FROM {:s}
           WHERE {:s} == ?'''

    return q.format(idcol, tbl, labelcol)


def _file_id_query(db):
    ''' constructs partial query to get fileset by file_id '''

    maptbl = list(db.get_maptable_names(MODELNAME, 'files'))
    if len(maptbl) != 1:
        raise FilesetError('expected only a single mapping table')
    maptbl = maptbl[0]
    q = '''SELECT {:s} FROM {:s} WHERE {:s} == ?'''
    return q.format(maptbl.leftid, maptbl.table, maptbl.rightid)


def _walker(dirname):
    ''' produce filenames using os.walk with default arguments (i.e. no symlinks)
    '''

    # start with toplevel dir itself
    yield dirname

    for pwd, dirs, filelist in _os.walk(dirname):
        for dname in dirs:
            dname = _os.path.join(pwd, dname)
            yield dname
        for fname in filelist:
            fname = _os.path.join(pwd, fname)
            yield fname
