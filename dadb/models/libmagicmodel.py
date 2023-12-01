''' libmagicmodel.py - models and functions related to libmagic

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

import multiprocessing as _multiprocessing
import os.path as _path
import magic as _magic
import sys
import apsw as _apsw

from .. import Database as _Database
from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import progresswrapper as _progresswrapper
from .. import exceptions as _exceptions

from . import filemodel as _filemodel


##################
# initialization #
##################

# initialize the magic module
_magictype = _magic.Magic()
_magicmime = _magic.Magic(mime=True)


##########
# MODELS #
##########

# model changelog
# 1 - initial version

MODELNAME = 'libmagic'
MODELDESCRIPTION = 'libmagic model for DADB'
MODELVERSION = 1

modeldef = _model_def(MODELNAME,
                     [_field_def('file', _filemodel.modeldef, nullable=False),
                      _field_def('libmagic', str),  # libmagic type
                      _field_def('mimetype', str)], # mimetype
                     MODELDESCRIPTION, MODELVERSION,
                     fail_on_dup=True)


#######
# API #
#######


def register_with_db(db):
    ''' register the models covered by this module '''

    _filemodel.register_with_db(db)
    db.register_model(modeldef)


def insert(db, fileid):
    ''' adds the mimetype for the file with the given id to the database.
    '''

    db.check_registered(MODELNAME)

    existing = _entry_by_fileid(db, fileid)

    if existing is not None:
        return existing

    # get the file, or raise exception if model or item does not exist
    f = db.modelitem(_filemodel.MODELNAME, fileid)

    # for non-regular files, or files without data, we simply
    # store None, None as magic and mimetype. This prevents
    # having to catch exceptions and running the libmagicmodel
    # multiple times on such items
    if f.ftype.value != _filemodel.Filetype.regular_file.value:
        mgc, mime = None, None
    elif f.data is None:
        mgc, mime = None, None
    elif f.data.stored is False:
        mgc, mime = None, None
    else:
        mgc, mime = _determine_filetype(f)

    # create and insert the modelitem
    m = db.make_modelitem('libmagic', file=fileid, libmagic=mgc, mimetype=mime)
    rowid = db.insert_modelitem(m)
    return rowid


def get(db, object_id):
    ''' returns the modelitem by its object_id '''

    try:
        return db.modelitem(MODELNAME, object_id)
    except _exceptions.NoSuchModelItemError:
        return None


def get_by_fileid(db, fileid, with_pkey=False):
    ''' return model item for file with given fileid '''

    id_ = _entry_by_fileid(db, fileid)
    if id_ is not None:
        item = db.modelitem(MODELNAME, id_)
        if with_pkey is True: return id_, item
        else: return item
    return None


def get_by_mimetype(db, mime_pattern, with_pkey=False):
    ''' generate sequence of modelitems for which mimetype matches mime_pattern

    The name_pattern argument uses the SQLite GLOB operator, which uses
    Unix file globbing syntax.
    '''

    # we use direct queries, so check model existence ourselves
    db.check_registered(MODELNAME)

    q = _mime_glob_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (mime_pattern,))
    for r in c:
        if with_pkey == True:
            yield (r[0], db.modelitem(MODELNAME, r[0]))
        else:
            yield db.modelitem(MODELNAME, r[0])


def get_by_libmagic(db, libmagic_pattern, with_pkey=False):
    ''' generate sequence of modelitems for which mimetype matches libmagic_pattern

    The name_pattern argument uses the SQLite GLOB operator, which uses
    Unix file globbing syntax.
    '''

    # we use direct queries, so check model existence ourselves
    db.check_registered(MODELNAME)

    q = _libmagic_glob_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (libmagic_pattern,))
    for r in c:
        if with_pkey == True:
            yield (r[0], db.modelitem(MODELNAME, r[0]))
        else:
            yield db.modelitem(MODELNAME, r[0])


def items(db, with_pkey=False):
    ''' yield modelitems '''

    return db.modelitems(MODELNAME, with_pkey)


def update(db, progress=False):
    ''' determine mimetype for *regular* files for which mimetype was not yet known '''

    db.check_registered(MODELNAME)

    # use all the cores!
    processes = _multiprocessing.cpu_count()

    # make sure we end existing transactions
    # so that we have a proper view of the current state
    # of the database before determining the list of unprocessed files
    try:
        db.end_transaction()
    except _apsw.SQLError as e:
        if e.args[0] == 'SQLError: cannot commit - no transaction is active':
            pass
        else:
            raise

    # collect the todolist
    todolist = list(_unprocessed_file_ids(db))

    if len(todolist) == 0:
        return

    if progress is True:
        # create a fake sequence wrapped in progresswrapper
        counter = (i for i in _progresswrapper(range(len(todolist)), '{:20s}'.format('    libmagic')))

    task_queue = _multiprocessing.Queue()
    done_queue = _multiprocessing.Queue()

    for fileid in todolist:
        task_queue.put(fileid)

    # Start worker processes
    workers = []
    for i in range(processes):
        p = _multiprocessing.Process(target=_multiproc_worker, args=(db, task_queue, done_queue))
        workers.append(p)
        p.start()

    # collect the results in a list
    results = list()
    for i in range(len(todolist)):
        res = done_queue.get()
        if progress is True:
            next(counter)
        results.append(res)

    if progress is True:
        # make sure progress bar indicates 100% when done
        list(counter)

    if len(results) != len(todolist):
        raise Exception("incorrect number of results obtained")

    # Tell child processes to stop
    donelist = []
    for i in range(processes):
        task_queue.put('STOP')
        donelist.append(done_queue.get())

    # verify if all workers received the STOP command
    if donelist != ['DONE']*processes:
        raise Exception("not all workers are done")

    # make sure all worker processess are cleaned up
    for p in workers:
        p.join()

    # insert the results into the database in one transaction
    db.begin_transaction()

    # disable duplicate checking, since we only process unprocessed files
    db.models['libmagic'].allow_duplicate_inserts()

    try:
        for res in results:
            if res is None:
                continue
            m = db.make_modelitem('libmagic', file=res[0], libmagic=res[1], mimetype=res[2])
            rowid = db.insert_modelitem(m)
    except:
        db.models['libmagic'].deny_duplicate_inserts()
        db.rollback_transaction()
        raise

    db.end_transaction()

    # revert in-memory changes so we can register normally
    db.models['libmagic'].deny_duplicate_inserts()


####################
# helper functions #
####################


# cache some of the queries used here
_Q_BY_FILEID = None
_MIMEGLOB_QUERY = None
_MAGICGLOB_QUERY = None


def _multiproc_worker(db, input, output):
    ''' determine libmagic for a list of fileids '''

    # make new connection to the database, make sure to only
    # access read-only by not registering the models
    subdb = _Database(db.dbname)
    subdb.load()

    for fileid in iter(input.get, 'STOP'):
        existing = _entry_by_fileid(subdb, fileid)
        if existing is not None:
            output.put(None)
            continue

        # get the file, or raise exception if model or item does not exist
        f = subdb.modelitem(_filemodel.MODELNAME, fileid)

        # for non-regular files, or files without data, we simply
        # store None, None as magic and mimetype. This prevents
        # having to catch exceptions and running the libmagicmodel
        # multiple times on such items
        if f.ftype.value != _filemodel.Filetype.regular_file.value:
            mgc, mime = None, None
        elif f.data is None:
            mgc, mime = None, None
        elif f.data.stored is False:
            mgc, mime = None, None
        else:
            mgc, mime = _determine_filetype(f)
        output.put((fileid, mgc, mime))

    # not really needed, since process will be killed, but do it anyway
    subdb.close()
    subdb = None
    # put DONE when STOP is received
    output.put('DONE')


def _determine_filetype(file_):
    ''' returns (filetype, mimetype) for the given _file modelitem '''

    # no need to keep track of position and reset pointer, since the
    # file_ object will be out of scope upon return of the insert function
    file_.data.seek(0)
    buf = file_.data.read(4096)
    # filetype
    mgc = _magictype.from_buffer(buf)
    # mimetype
    mime = _magicmime.from_buffer(buf)
    return mgc, mime


def _unprocessed_file_ids(db):
    ''' generates file_ids for which mimetype is not yet determined '''

    # we need primary key from file table and 'file' column from mimetype table
    ftbl = db.get_tblname(_filemodel.MODELNAME)
    fid = db.get_colname(_filemodel.MODELNAME)
    mtbl = db.get_tblname(MODELNAME)
    mfid = db.get_colname(MODELNAME, 'file')
    # we are only interested in regular files...
    ftype = db.get_colname(_filemodel.MODELNAME, 'ftype')
    regular = _filemodel.Filetype.regular_file.value
    # ...that are not empty
    fsize = db.get_colname(_filemodel.MODELNAME, 'size')

    # select those files which have no entry in mimetype table
    q = '''SELECT {:s}.{:s} FROM {:s}
           WHERE {:s}.{:s} NOT IN
           (SELECT {:s}.{:s}
           FROM {:s}) AND {:} is {:} AND {:} is not 0'''
    q = q.format(ftbl, fid, ftbl, ftbl, fid, mtbl, mfid, mtbl,
                 ftype, regular, fsize)

    # NOTE: use a dedicated cursor to prevent nesting issues
    results = db.dbcon.cursor().execute(q)

    for restpl in results:
        fileid = restpl[0]
        yield fileid


def _entry_by_fileid(db, fileid):
    ''' returns rowid of mimetype entry by the given fileid '''

    global _Q_BY_FILEID

    if _Q_BY_FILEID is None:
        # get field and table names
        mtbl = db.get_tblname(MODELNAME)
        mfid = db.get_colname(MODELNAME, 'file')
        mkey = db.get_colname(MODELNAME)
        _Q_BY_FILEID='SELECT {:s} FROM {:s} WHERE {:s} == ?'.format(mkey, mtbl, mfid)

    results = list(db.dbcon.cursor().execute(_Q_BY_FILEID, (fileid,)))
    if len(results) == 0:
        return None
    elif len(results) == 1:
        return results[0][0]
    raise RuntimeError('corrupt database, more than one entry in mimetype table')


def _mime_glob_query(db):
    ''' constructs (or fetches from cache) partial query to get item by mimetype '''

    # use cached version if available
    global _MIMEGLOB_QUERY
    if _MIMEGLOB_QUERY is not None:
        return _MIMEGLOB_QUERY

    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    pathcol = db.get_colname(MODELNAME, 'mimetype')
    q = '''SELECT {:s}
           FROM {:s}
           WHERE {:s} GLOB ?'''

    q = q.format(idcol, tbl, pathcol)
    _MIMEGLOB_QUERY = q
    return _MIMEGLOB_QUERY


def _libmagic_glob_query(db):
    ''' constructs (or fetches from cache) partial query to get item by mimetype '''

    # use cached version if available
    global _MAGICGLOB_QUERY
    if _MAGICGLOB_QUERY is not None:
        return _MAGICGLOB_QUERY

    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    pathcol = db.get_colname(MODELNAME, 'libmagic')
    q = '''SELECT {:s}
           FROM {:s}
           WHERE {:s} GLOB ?'''

    q = q.format(idcol, tbl, pathcol)
    _MAGICGLOB_QUERY = q
    return _MAGICGLOB_QUERY
