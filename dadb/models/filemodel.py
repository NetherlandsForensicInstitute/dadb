''' filemodel.py - file model for DADB

Copyright (c) 2023 Netherlands Forensic Institute - MIT License

Conceptually, a file is an object that contains the most common metadata
associated with a file, directory or symlink. It also (optionally) contains a
Data object, which contains the data associated or contained within the file.

Note that only the basic file system properties as returned by the stat command
are included here. If you need additional properties for file entries, you can
wrap the filemodel inside another model with additional properties.

The file model as defined here does not allow duplicate entries to be inserted,
which comes at a significant performance cost when inserting a large amount of
files, since each insert will check if a duplicate exists. When the caller of
the insert or update function already knows it is not going to insert
duplicates, duplicate checking can be (temporary) disabled via the
disable_duplicate_checking database function to speed things up. The user_tag
field can be used to enforce uniqueness when all other fields are equal.

When filemodel items are inserted as part of another model (implicit insert),
it will check for duplicates and if one is found, it is assumed that a
reference to the existing file item should be made, instead of a new
(duplicate) entry.
'''

from datetime import datetime as _datetime
from enum import Enum as _Enum
import os as _os
import stat as _stat
from pytz import utc as _utc
import mmap as _mmap

from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import Data as _Data
from .. import _exceptions


####################
# MODEL DEFINITION #
####################

# model changelog:
# 1 - initial model version
# 2 - ftype and deleted field may no longer be NULL
# 3 - remove file system as one of the fields
# 4 - add device number

MODELNAME = 'file'
MODELDESCRIPTION = 'file model for DADB'
MODELVERSION = 4


class Filetype(_Enum):
    ''' filetypes, derived from the stat man file '''

    unknown = 0
    directory = 0o040000
    character_device = 0o020000
    block_device = 0o060000
    regular_file = 0o100000
    fifo = 0o010000
    symbolic_link = 0o120000
    socket = 0o140000


class Deleted(_Enum):
    ''' deleted state of the file in the file system '''

    intact = 0
    deleted = 1
    unknown = 2


modeldef = _model_def(MODELNAME,
                      [_field_def('name', str, nullable=False),
                       _field_def('path', str, nullable=False, preview=True),
                       _field_def('inode', int),       # inode number
                       _field_def('device', int),      # device number
                       _field_def('size', int, nullable=False),
                       _field_def('nlinks', int),      # nr of hardlinks
                       _field_def('mode', int),        # numeric file mode
                       _field_def('ftype', Filetype, nullable=False),  # posix file type derived from mode
                       _field_def('perms', str),       # permissions derived from mode
                       _field_def('uid', int),         # user id
                       _field_def('gid', int),         # group id
                       _field_def('mtime', _datetime), # contents modification time
                       _field_def('atime', _datetime), # last access time
                       _field_def('ctime', _datetime), # metadata change time
                       _field_def('btime', _datetime), # creation or birth time
                       _field_def('dtime', _datetime), # deletion time
                       _field_def('deleted', Deleted, nullable=False), # deletion state
                       _field_def('linkpath', str),    # path of symlink target
                       _field_def('data', _Data),      # data stored in file
                       _field_def('user_tag', str)],   # user provided tag
                      MODELDESCRIPTION, MODELVERSION,
                      implicit_dedup=True, fail_on_dup=True)


#######
# API #
#######


def register_with_db(db):
    ''' register this model to the given database '''

    db.register_enum(Filetype, MODELDESCRIPTION, MODELVERSION)
    db.register_enum(Deleted, MODELDESCRIPTION, MODELVERSION)
    db.register_model(modeldef)


def insert(db, filename, user_tag=None, do_mmap=False):
    ''' add file with given filename to the database

    If mmap is True, the actual file data will not be stored in the database,
    only it's meta-data (size and hashes). Instead we return the rowid *and* a
    memory mapped version of the file so that the caller can process the file
    data further. Caller is responsible for closing the mmapped file

    NOTE: timestamps originating from the local file system are assumed to be
          UTC. This might be incorrect if you have a naive file system!
    '''

    filename = _os.path.expanduser(filename)
    filename = _os.path.abspath(filename)
    if not _os.path.exists(filename):
        raise ValueError('file does not exist')

    # defaults
    name = _os.path.basename(filename)
    path = filename
    deleted = Deleted.intact
    btime = None
    dtime = None
    linkpath = None
    data_obj = None

    # use stat to obtain file properties (symlinks are not followed by lstat)
    r = _os.lstat(filename)
    # NOTE: we assume UTC here, this might be incorrect.
    atime = _datetime.fromtimestamp(r.st_atime, _utc)
    ctime = _datetime.fromtimestamp(r.st_ctime, _utc)
    mtime = _datetime.fromtimestamp(r.st_mtime, _utc)
    ftype = _get_filetype(_stat.S_IFMT(r.st_mode))
    perms = _stat.filemode(r.st_mode)
    inode = r.st_ino
    device = r.st_dev
    mode = r.st_mode
    uid = r.st_uid
    gid = r.st_gid
    size=r.st_size
    nlinks = r.st_nlink

    # start transaction, since we also insert a Data object
    started_transaction = db.begin_transaction()

    if _os.path.islink(filename):
        # symlinks have same properties as normal files, and a linkpath
        linkpath = _os.readlink(filename)

    elif _os.path.isdir(filename):
        # nlink output in stat refers to number of subdirs,
        # and most systems do not allow hardlink to directories
        nlinks = None

    elif _os.path.isfile(filename):
        with open(filename, 'rb') as data:
            if do_mmap is True:
                # determine size
                data.seek(0, 2)
                size = data.tell()
                data.seek(0)
                mmapped = _mmap.mmap(data.fileno(), data.tell(), access=_mmap.ACCESS_READ)
                try:
                    # store metadata for data object, but not data itself
                    dataid = db.insert_unstored_data(mmapped)
                except:
                    if started_transaction is True:
                        db.rollback_transaction()
                    raise
            else:
                try:
                    dataid = db.insert_data(data)
                except:
                    if started_transaction is True:
                        db.rollback_transaction()
                    raise
        # make sure the data object is a dadb.Data object
        data_obj = db.get_data(dataid)

    else:
        if started_transaction is True:
            db.rollback_transaction()
        raise ValueError('given path is not a link, directory or file')

    # create and insert the modelitem
    try:
        m = db.make_modelitem(MODELNAME, name=name, path=path, inode=inode,
                device=device, mode=mode, ftype=ftype, perms=perms, atime=atime,
                ctime=ctime, mtime=mtime, nlinks=nlinks, deleted=deleted, uid=uid,
                gid=gid, size=size, linkpath=linkpath, data=data_obj,
                user_tag=user_tag)

        rowid = db.insert_modelitem(m)
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    if started_transaction is True:
        db.end_transaction()

    if do_mmap is True:
        return rowid, mmapped
    else:
        return rowid


def get(db, object_id):
    ''' returns the modelitem by its object_id '''

    try:
        return db.modelitem(MODELNAME, object_id)
    except _exceptions.NoSuchModelItemError:
        return None


def get_by_path(db, name_pattern, with_pkey=False):
    ''' generates a sequence of file modelitems with the given name pattern

    The name_pattern argument uses the SQLite GLOB operator, which uses
    Unix file globbing syntax.
    '''

    # we use direct queries, check if model is registered
    db.check_registered(MODELNAME)

    q = _path_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (name_pattern,))
    for r in c:
        if with_pkey == True:
            yield (r[0], db.modelitem(MODELNAME, r[0]))
        else:
            yield db.modelitem(MODELNAME, r[0])


def get_by_size(db, minsize, maxsize, with_pkey=False):
    ''' generates a sequence of file modelitems with given size constraints

    The results yielded are ordered by size from small to large
    '''

    # we use direct queries, so check model existence ourselves
    db.check_registered(MODELNAME)

    q = _size_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (minsize, maxsize))
    for r in c:
        if with_pkey == True:
            yield (r[0], db.modelitem(MODELNAME, r[0]))
        else:
            yield db.modelitem(MODELNAME, r[0])


def items(db, with_pkey=False):
    ''' yield modelitems '''

    return db.modelitems(MODELNAME, with_pkey)


def files_by_sha256(db, ids_only=False):
    ''' generate a sequence of (sha256, files) tuples for all files with data

    The files component of the result tuples is a list of file items or a list
    of fileids, if the ids_only argument is True.

    Note that only files are returned that actually have *stored* data. Files
    with no data or for which the data is not present in the database is not
    included. Rationale: this function can be used to search in the contents of
    all files, without having to search through the same contents multiple
    times.
    '''

    ftbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    sha256col = db.prefix + 'sha256'
    storecol = db.prefix + 'stored'
    dtbl = db.prefix + 'data'
    datacol = db.get_colname(MODELNAME, 'data')

    q = f"SELECT {ftbl}.{idcol}, {datacol} , {sha256col} FROM {ftbl} JOIN {dtbl} ON {datacol} == {dtbl}.{idcol} WHERE {datacol} IS NOT NULL AND {dtbl}.{storecol} == 1 ORDER BY {sha256col}"

    c = db.dbcon.cursor()
    c.execute(q)
    res = c.fetchall()

    prev_sha256 = None
    for (fileid, dataid, sha256) in res:
        if prev_sha256 is None:
            fileids = [fileid]
            prev_sha256 = sha256
        elif sha256 == prev_sha256:
            fileids.append(fileid)
        else:
            if ids_only is True:
                yield (prev_sha256, fileids)
            else:
                yield (prev_sha256, [get(db, fid) for fid in fileids])
            prev_sha256 = sha256
            fileids=[fileid]

    if fileids != []:
        if ids_only is True:
            yield (sha256, fileids)
        else:
            yield (sha256, [get(db, fid) for fid in fileids])


def file_blocks(db, file_, blocksize=52428800, overlap=0):
    ''' generate a sequence of blocks with optional overlap for the given file

    For each subsequent block, this function seeks back 'overlap' bytes in
    order to allow for carving at block-boundaries. The caller has to make sure
    that the overlap is larger than the pattern that is being searched for.

    Default values for blocksize and overlap are 50MB and 0 bytes respectively,
    which causes this function to behave like a normal block reading function.
    If overlap is set to some positive value, the overlap is used to search
    back the corresponding amount of bytes. If your search pattern is larger
    than overlap, you might miss some results that are on a block boundary, so
    increment the overlap if required.

    In order to keep this function reasonably fast, no check is done on whether
    the given file actually has stored data. This is something the caller is
    responsible for.
    '''

    if isinstance(file_, int):
        file_ = get(db, file_)

    offset=0
    file_.data.seek(0)
    # read the first block
    bytes_ = file_.data.read(blocksize)
    while bytes_ != b'':
        yield (offset, bytes_)
        if file_.data.tell() != file_.data.length:
            # seek back overlap bytes and read next block, to make sure
            # we are not excluding hits on block-boundaries
            file_.data.seek(-overlap, 1)
            offset = file_.data.tell()
            bytes_ = file_.data.read(blocksize)
        else:
            break


def file_count(db):
    ''' return total number of files in the database '''

    tbl = db.get_tblname(MODELNAME)
    q = ''' SELECT count(*) FROM {:s} '''
    q = q.format(tbl)
    c = db.dbcon.cursor()
    c.execute(q)
    res = c.fetchall()
    return res[0][0]


def has_data(db, file_):
    ''' return True if the given file(id) has stored data '''

    if isinstance(file_, int):
        f = get(db, file_)
        fileid = file_
    else:
        f = file_
        fileid = db.modelitem_id(f)

    if f.ftype.value != Filetype.regular_file.value:
        return False
    if f.size == 0:
        return False
    if f.data is None:
        return False
    if f.data.stored is False:
        return False

    return True


####################
# helper functions #
####################


# module global variables to store specific queries
_GETPATH_QUERY = None
_GETSIZE_QUERY = None


def _get_filetype(value):
    ''' converts numeric filetype to Enum type '''

    for f in Filetype:
        if f.value == value:
            return f
    raise ValueError('unknown filetype value provided: {:d}'.format(value))


def _path_query(db):
    ''' (construct and) get query to fetch files by path '''

    # use cached version if available
    global _GETPATH_QUERY
    if _GETPATH_QUERY is not None:
        return _GETPATH_QUERY

    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    pathcol = db.get_colname(MODELNAME, 'path')
    q = '''SELECT {:s}
           FROM {:s}
           WHERE {:s} GLOB ?'''

    q = q.format(idcol, tbl, pathcol)
    _GETPATH_QUERY = q
    return _GETPATH_QUERY


def _size_query(db):
    ''' (construct and) get query to fetch files by size '''

    # use cached version if available
    global _GETSIZE_QUERY
    if _GETSIZE_QUERY is not None:
        return _GETSIZE_QUERY

    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    sizecol = db.get_colname(MODELNAME, 'size')
    q = '''SELECT {:s}
           FROM {:s}
           WHERE {:s} >= ? and {:s} <= ? ORDER BY {:s} '''

    q = q.format(idcol, tbl, sizecol, sizecol, sizecol)
    _GETSIZE_QUERY = q
    return _GETSIZE_QUERY
