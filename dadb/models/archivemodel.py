''' archivemodel.py - models and functions related to extraction of archives

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

import libarchive as _libarchive
import zipfile as _zipfile
import tarfile as _tarfile
import stat as _stat
import os as _os
from enum import Enum as _Enum
from datetime import datetime as _datetime
from pytz import utc as _utc
from io import BytesIO as _BytesIO
import tempfile as _tempfile
from struct import unpack as _unpack

# test if we have the proper version of libarchive
if not hasattr(_libarchive, 'file_reader'):
    raise ModuleNotFoundError("Incorrect version of libarchive detected, you need libarchive-c")

from .. import Database as _Database
from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import progresswrapper as _progresswrapper
from .. import exceptions as _exceptions

from . import filemodel as _fmodel
from . import filesetmodel as _fsetmodel
from . import libmagicmodel as _libmagicmodel
from . import fileparentmodel as _fparentmodel


##########
# MODELS #
##########

# changelog:
# 1 - initial model version

MODELNAME='archive'  # a (compressed) file that contains files
MODELDESCRIPTION='archive model for DADB'
MODELVERSION = 1


class ArchiveType(_Enum):
    ''' type of archive '''

    Zip = 1
    Tar = 2
    Cpio = 3
    SevenZip = 4  # a.k.a. 7Zip


modeldef = _model_def(MODELNAME,
                      [_field_def('file', _fmodel.modeldef, nullable=False),
                       _field_def('contents', _fsetmodel.modeldef),
                       _field_def('error', str),
                       _field_def('type_', ArchiveType, nullable=False)],
                      MODELDESCRIPTION, MODELVERSION,
                      implicit_dedup=True, fail_on_dup=True)


# files that can be extracted using zipfile
ZIP_MIMES = ['application/zip', 'application/java-archive']

# files that can be extracted using tarfile
# NOTE: some mime types can be a compressed tar, or simply a compressed binary file
#       (i.e. application/gzip and application/x-bzip2). If this is a
#       tar file it is more efficient to process directly with the archivemodel, so
#       added the mimetype here as well. If it is some other compressed file, the insert will
#       result in an entry with an error: 'file could not be opened successfully'
TAR_MIMES = ['application/x-tar', 'application/gzip', 'application/x-bzip2']

# types that can be extracted using more generic libarchive
LIBARCHIVE_MAGICS = {'cpio archive' : ArchiveType.Cpio}
LIBARCHIVE_MIMES = {'application/x-7z-compressed' : ArchiveType.SevenZip}


# we can safely disable duplicate checking for these models during insertion
# of zipmodel items, since each file is only processed exactly once and
# we add a unique user_label to each extracted file to make them unique
DUPCHECK_DISABLE = ['file', 'fileparent']


#######
# API #
#######


def register_with_db(db):
    ''' register the model and its dependencies to the database '''

    _fmodel.register_with_db(db)
    _fsetmodel.register_with_db(db)
    _fparentmodel.register_with_db(db)
    _libmagicmodel.register_with_db(db)
    db.register_enum(ArchiveType, MODELDESCRIPTION, MODELVERSION)
    db.register_model(modeldef)


def insert(db, fileid):
    ''' extracts the given file if it is an archive and not extracted yet '''

    db.check_registered(MODELNAME)

    # check if the file was already processed
    existing = _entry_by_fileid(db, fileid)
    if existing is not None:
        return existing

    # get the file with the given fileid
    f = _fmodel.get(db, fileid)

    # silently ignore files with no data or non-regular files
    if f.ftype.value != _fmodel.Filetype.regular_file.value:
        return None
    if f.size == 0:
        return None
    if f.data is None:
        return None
    if f.data.stored is False:
        return None

    # disable duplicate checking, since processed archives are not processed
    # twice, and because we add specific user tags to each extracted file
    # NOTE: this might lead to duplicates if the file itself contains exact
    # duplicates, but this should normally not occur.
    db.disable_duplicate_checking(_fmodel.MODELNAME)
    db.disable_duplicate_checking(_fparentmodel.MODELNAME)


    # make sure everything happens in a single transaction
    started_transaction = db.begin_transaction()

    # determine the libmagic (if not already determined)
    try:
        _libmagicmodel.insert(db, fileid)
    except:
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)
        if started_transaction is True:
            db.rollback_transaction()
        raise

    filemagic = _libmagicmodel.get_by_fileid(db, fileid)

    if filemagic is None:
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)
        if started_transaction is True:
            db.rollback_transaction()
        raise ValueError("filemagic should not be None at this point")

    # determine the type of archive from the libmagic result
    archive_type = _detect_type(filemagic)
    if archive_type is None:
        if started_transaction is True:
            db.end_transaction()
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)
        return None

    # get the apropriate extraction function
    extract_function = _get_extract_function(archive_type)

    # label for the resulting fileset
    label = 'extracted from file {:} by archivemodel'.format(fileid)

    # in order to be able to distinguish between errors in unpacking
    # and other errors, we limit the number of function calls in each try clause,
    # which is why we need several try/except constructs here

    # call the extract function on the file and log an error if it fails
    try:
        members = extract_function(db, f, fileid)
    except Exception as e:
        # create modelitem with the error
        m = db.make_modelitem(MODELNAME, file=fileid, contents=None, error=repr(e), type_=archive_type)
        rowid = db.insert_modelitem(m)
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)
        if started_transaction is True:
            db.end_transaction()
        return rowid

    # If we get here, opening the file as archive worked.
    # Iterate over the members and build the fileset
    rowids = []

    try:
        for member in members:
            rowid = db.insert_modelitem(member)
            rowids.append(rowid)
    except Exception as e:
        # some error occurred during extraction
        if len(rowids) == 0:
            fset = None
        else:
            # keep the partially extracted files
            fset = _fsetmodel.insert(db, label, tuple(rowids))
            # insert parent relations and set root to original fileid
            _fparentmodel.insert_files(db, rowids, fileid)
        # create modelitem with error and potential fileset
        m = db.make_modelitem(MODELNAME, file=fileid, contents=fset, error=repr(e), type_=archive_type)
        rowid = db.insert_modelitem(m)
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)
        if started_transaction is True:
            db.end_transaction()
        return rowid

    # if we get here, the file was extracted without error, so all other
    # errors should not be logged in the archive modelitem, but should be raised instead
    try:
        if len(rowids) == 0:
            fset = None
        else:
            fset = _fsetmodel.insert(db, label, tuple(rowids))
            # insert the relations between the files in the archive, using fileid as root
            _fparentmodel.insert_files(db, rowids, fileid)

        # create and insert the archivemodel item
        m = db.make_modelitem(MODELNAME, file=fileid, contents=fset, error=None, type_=archive_type)
        rowid = db.insert_modelitem(m)
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise
    finally:
        # enable duplicate checking again always!
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)

    if started_transaction is True:
        db.end_transaction()

    return rowid


def update(db, progress=False, maxrounds=5):
    ''' extract unprocessed archives into new file objects.

    Maxrounds limits the max number of extraction rounds '''

    db.check_registered(MODELNAME)

    round_ = 0
    while round_ < maxrounds:
        # run libmagic over the file model items
        # (libmagic manages it's own transaction)
        _libmagicmodel.update(db, progress)

        # keep track of processed files
        c = 0

        # perform each round in a transaction, as to prevent rolling
        # back all rounds, when error occurs in last round
        db.begin_transaction()

        # try to extract new archives
        try:
            c += _archiveround(db, progress)
            db.end_transaction()
        except:
            db.rollback_transaction()
            raise

        if c == 0:
            # No files extracted this round, no need to continue
            break

        round_+= 1


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


def items(db, with_pkey=False):
    ''' yield modelitems '''

    return db.modelitems(MODELNAME, with_pkey)


def extracted_files(db):
    ''' yield sequence of files of successfully extracted files without errors '''

    for fid in _extracted_files(db):
        yield _fmodel.get(db, fid)


def processed_file_ids(db):
    ''' yield sequence of fileids of successfully extracted files without errors '''

    for fid in _extracted_files(db):
        yield fid


def drop_original_file_data(db, archive_id):
    ''' drop the blocks of the original file if the extraction was successfull '''

    m = get(db, archive_id)
    if m.error is not None:
        raise ValueError("archive extraction had an error, can not drop data via this function")
    if m.contents is None:
        raise ValueError("archive extraction produced no outfile, can not drop data via this function")

    if m.file.data.stored is False:
        return

    # if we get here, we can drop the original file blocks
    started_transaction = db.begin_transaction()

    try:
        m.file.data.drop_blocks()
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    if started_transaction is True:
        db.end_transaction()


def drop_all_original_file_data(db, minsize=0):
    ''' drop the original data for all decompressed files with a size larger than minsize

    the default minsize of 0 causes *all* original files to be dropped, change to a higher
    value if you want to keep the data of small compressed files
    '''

    started_transaction = db.begin_transaction()
    try:
        for fileid in _extracted_files(db):
            f = _fmodel.get(db, fileid)
            if f.data.stored is False:
                continue
            if f.size >= minsize:
                f.data.drop_blocks()
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    if started_transaction is True:
        db.end_transaction()


####################
# helper functions #
####################

# cache some of the queries used
_Q_BY_FILEID = None


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
    raise RuntimeError('corrupt database, more than one entry in table')


def _detect_type(libmagicitem):
    ''' return the archive type or None if the type is not recognized '''

    # NOTE: order matters here, since libarchive gives less meta-data for some
    # archive types such as ZIP and TAR

    # check if this is a ZIP type
    if libmagicitem.mimetype in ZIP_MIMES:
        return ArchiveType.Zip

    if libmagicitem.mimetype in TAR_MIMES:
        return ArchiveType.Tar

    # finally check if this file can be extracted using generic libarchive
    if libmagicitem.libmagic is None:
        return None

    if libmagicitem.mimetype in LIBARCHIVE_MIMES:
        return LIBARCHIVE_MIMES[libmagicitem.mimetype]

    for magic, type_ in LIBARCHIVE_MAGICS.items():
        if magic in libmagicitem.libmagic:
            return type_

    return None


def _archiveround(db, progress=False):
    ''' unpack currently unprocessed archives '''

    todolist = list(_unprocessed_file_ids(db))

    if len(todolist) == 0:
        return 0

    if progress is True:
        todolist = _progresswrapper(todolist, '{:20s}'.format('    archive'))

    c = 0
    for id_ in todolist:
        rowid = insert(db, id_)
        c+=1

    return c


def _unprocessed_file_ids(db):
    ''' generates file_ids that have not yet been processed as archive '''

    # prepare query for files with proper mimetype or substring in magic
    mimetypes = ZIP_MIMES + TAR_MIMES + [k for k in LIBARCHIVE_MIMES.keys()]
    magic_substrings = LIBARCHIVE_MAGICS
    libmagictable = db.get_tblname(_libmagicmodel.MODELNAME)
    mimetype = db.get_colname(_libmagicmodel.MODELNAME, 'mimetype')
    libmagic = db.get_colname(_libmagicmodel.MODELNAME, 'libmagic')
    fileid = db.get_colname(_libmagicmodel.MODELNAME, 'file')
    mgc = ['{:s}.{:s} LIKE "%{:s}%"'.format(libmagictable, libmagic, t) for t in magic_substrings]
    mimes = ['{:s}.{:s} == "{:s}"'.format(libmagictable, mimetype, t) for t in mimetypes]
    where = ' OR '.join(mgc+mimes)
    candidates = 'SELECT {:s}.{:s} FROM {:s} WHERE ({:s})'.format(libmagictable, fileid, libmagictable, where)

    # and we need only those files that are not already extracted
    my_table = db.get_tblname(MODELNAME)
    my_fileid = db.get_colname(MODELNAME, 'file')
    processed_files = 'SELECT {:s}.{:s} FROM {:s}'.format(my_table, my_fileid, my_table)

    # exclude files that already have children (i.e. already decompressed?)
    parenttbl = db.get_tblname(_fparentmodel.MODELNAME)
    parentid = db.get_colname(_fparentmodel.MODELNAME, 'parent')
    parents = 'SELECT {:s}.{:s} FROM {:s}'.format(parenttbl, parentid, parenttbl)

    # select those files that are not processed and are not parents
    q = '''{:s} AND ({:s}.{:s} NOT IN ({:s})) AND ({:s}.{:s} NOT IN ({:s}))'''
    q = q.format(candidates, libmagictable, fileid, processed_files, libmagictable, fileid, parents)

    # fetch all results and store in a list of file ids and use dedicated
    # cursor to prevent issues with aborted SELECT statements
    results = list(db.dbcon.cursor().execute(q))

    for restpl in results:
       fileid = restpl[0]
       yield fileid


def _generate_intermediate_dirs(db, dirs_in_filepaths, created_dirs, fileid, device=None):
    ''' some archives do not have explicit entries for each directory. This
    function is used to generate such entries to make sure the extraction
    results in a strict file-hierarchy '''

    # create virtual entries for the intermediate directories for which
    # no separate zipinfo item was present
    user_tag = 'generated intermediate directory as part of extraction of file {:d}'
    user_tag = user_tag.format(fileid)

    generated_dirs = set()

    # generate the directories that where not explicitly stored in the zip-file
    for dirpath in dirs_in_filepaths:
        # iterate over all parents of current dir
        for dirname in _dir_parents(dirpath):
            if dirname in created_dirs:
                # stored explicitly, do not generate
                continue
            elif dirname in generated_dirs:
                # already generated earlier
                continue
            name = _os.path.basename(dirname)
            generated_dirs.add(dirname)
            m = db.make_modelitem(_fmodel.MODELNAME, name=name, path=dirname, size=0,
                                  ftype=_fmodel.Filetype.directory, device=device,
                                  user_tag=user_tag, deleted=_fmodel.Deleted.intact)
            yield m


def _dir_parents(path):
    ''' yield current path and all parents stripping of basename recursively
    '''

    yield path
    dirname = _os.path.dirname(path)
    if dirname != '' and dirname != _os.path.sep:
        for d in _dir_parents(dirname):
            yield d


def _files_from_libarchive(db, fileitem, fileid):
    ''' yields file objects from the archive in the given file as recognized by libarchive

    This function can be used for archive types for which we do not have a dedicated
    module with more details for the specific archive type.

    This method create a temporary file with the data of the file with the
    given fileid  The reason for this is that libarchive can not deal with
    DADB Data objects due to UnsupportedOperation: fileno. Looking into
    libarchive sources reveals that the fileno is used to call os.stat with the
    given fileno, so we can not just make up a fileno. Instead, copy the file
    data to a tempfile and operate on that tempfile '''

    if fileitem.data is None:
        # nothing to yield
        return

    if fileitem.data.seekable() is True:
        fileitem.data.seek(0)

    # copy all data into a tempfile
    tmpfile = _tempfile.NamedTemporaryFile()
    tmpfile.file.write(fileitem.data.read())
    tmpfile.file.seek(0)

    # attempt to parse as archive
    with _libarchive.file_reader(tmpfile.name) as archive:
        # intermediate directories do not always have a separate entry
        # so we must produce these ourselve. Keep track of all directory
        # names that are present in the filepaths and keep track of all
        # directories we have already created
        dirs_in_filepaths = set()
        created_dirs = set()

        for e in archive:

            if e.linkname != e.linkpath:
                raise _exceptions.AssumptionBrokenError("linkname and linkpath are two different concepts apparently")

            if e.name != e.path != e.pathname:
                raise _exceptions.AssumptionBrokenError("name, path and pathname are different concepts apparently")

            # separate filename from path
            path = e.pathname
            fname = _os.path.basename(path)

            # Note: This could be simplified similar to zip, but it works so kept as is for now.
            if path.endswith(_os.path.sep):
                # In some archive types (i.e. 7z), the pathname of
                # directories may end with a path separator. In this
                # case, the path and fname will be incorrect, since
                # basename simply performs split operations under the hood.
                # In this case, we expect fname to be ''. Change to
                # the last directory in the path
                if fname != '':
                    raise _exceptions.AssumptionBrokenError("expected fname to be empty string here")
                # split by path separator and take the second to last component
                fname = path.split(_os.path.sep)[-2]
                # and strip the trailing slash off from the path
                path = path.rstrip(_os.path.sep)

            # check mode and filetype properties
            mode_type = _stat.S_IFMT(e.mode)
            if mode_type != e.filetype:
                raise _exceptions.AssumptionBrokenError("reported filetype does not match mode")
            ftype = _fmodel._get_filetype(mode_type)

            # and check permissions as string
            perms = _stat.filemode(e.mode)
            if perms != e.strmode.decode():
                raise _exceptions.AssumptionBrokenError("reported permissions do not match mode")

            # NOTE: mtime will often be UTC, but we are not sure!
            mtime = _datetime.fromtimestamp(e.mtime, _utc)

            # keep track of the directory names in order to know
            # which intermediate directories should be created
            dirname = _os.path.dirname(path)
            if dirname != '':
                dirs_in_filepaths.add(dirname)

            if e.isdir is True:
                # treat dir separately, in order to detect intermediate dirs
                if ftype != _fmodel.Filetype.directory:
                    raise _ValueError("convenience property disagrees with mode from filetype")
                # make note of the full path of the directory
                created_dirs.add(path)
            else:
                # and detect the actual file-type
                if e.isblk is True and ftype != _fmodel.Filetype.block_device:
                    raise _ValueError("convenience property disagrees with mode from filetype")
                elif e.ischr is True and ftype != _fmodel.Filetype.character_device:
                    raise _ValueError("convenience property disagrees with mode from filetype")
                elif e.isdev is True and ftype != _fmodel.Filetype.device:
                    raise _ValueError("convenience property disagrees with mode from filetype")
                elif e.isfifo is True and ftype != _fmodel.Filetype.fifo:
                    raise _ValueError("convenience property disagrees with mode from filetype")
                # assume that isfile and isreg are equivalent
                elif e.isfile is True:
                    if e.isreg is False:
                        raise _exceptions.AssumptionBrokenError("assumed that isfile and isreg are equivalent")
                    if ftype != _fmodel.Filetype.regular_file:
                        raise _ValueError("convenience property disagrees with mode from filetype")
                # assume that islnk and issym are equivalent
                elif e.islnk is True:
                    if e.issym is False:
                        raise _exceptions.AssumptionBrokenError("assumed that islnk and issym are equivalent")
                    if ftype != _fmodel.Filetype.symbolic_link:
                        raise _ValueError("convenience property disagrees with mode from filetype")
                elif e.issock is True and ftype != _fmodel.Filetype.socket:
                    raise _ValueError("convenience property disagrees with mode from filetype")

            # add user_tag to prevent duplicates from different archives
            # to be treated as such
            user_tag = 'extracted from file {:d} by archivemodel (libarchive-c)'.format(fileid)

            # extract the data into a BytesIO object
            data = None
            if e.isfile:
                data = _BytesIO()
                for b in e.get_blocks():
                    data.write(b)

            # create the modelitem
            m = db.make_modelitem('file', name=fname, path=path,
                                  size=e.size, ftype=ftype, perms=perms,
                                  mode=e.mode, deleted=_fmodel.Deleted.intact,
                                  linkpath=e.linkpath,
                                  uid=None, gid=None, mtime=mtime,
                                  data=data,user_tag=user_tag)
            yield m

    for d in _generate_intermediate_dirs(db, dirs_in_filepaths, created_dirs, fileid):
        yield d


def _files_from_zip(db, fileobj, fileid):
    ''' yields file object from the zip-archive contained in the given file '''

    if fileobj.data is None:
        # nothing to yield
        return

    # make sure we start at the beginning
    if fileobj.data.seekable() is True:
        fileobj.data.seek(0)

    # try if we can open the file as a zipfile
    # (will raise BadZipFile error upon failure)
    zf = _zipfile.ZipFile(fileobj.data)

    # intermediate directories do not always have a separate entry
    # so we must produce these ourselve. Keep track of all directory
    # names that are present in the filepaths and keep track of all
    # directories we have already created
    dirs_in_filepaths = set()
    created_dirs = set()

    for name in zf.namelist():

        zinfo = zf.NameToInfo[name]

        # some zip tools store additional metadata, attempt to
        # extract this from the extra field
        inode, device, uid, gid = None, None, None, None
        mtime, atime, ctime, btime = None, None, None, None
        if len(zinfo.extra) > 0:
            try:
                res = _parse_extra(zinfo.extra)
                if res is not None:
                    mtime, atime, ctime, btime, uid, gid, inode, device = res
            except Exception as e:
                # ignore the extra field if a parsing error ocurred
                pass

        size = zinfo.file_size

        # zinfo.filename contains full path
        path = zinfo.filename
        # strip of trailing path separator
        path = path.rstrip(_os.path.sep)
        # Some ZIP files have absolute paths (i.e. starting with '/').
        # The unzip command strips the forward slash to prevent unpacking
        # over the root filesystem. We need to do the same to prevent our
        # file-hierarchy to be messed up.
        if path.startswith('/'):
            path = path.lstrip('/')
        # determine filename
        fname = _os.path.basename(path)

        password_needed = False

        # keep track of the intermediate directories that are needed so we
        # can check if they are all explicitly created.
        # NOTE: this was previously only done for non-directories,
        # but we encountered a zipfile with some empty directories
        # for which the intermediate directories had no separate entries
        # so this was changed both here and in the other files_from... functions
        dirname = _os.path.dirname(path)
        if dirname != '':
            dirs_in_filepaths.add(dirname)

        if zinfo.is_dir() is True:
            ftype = _fmodel.Filetype.directory
            created_dirs.add(path)
            data = None
        else:
            # this is a regular file
            ftype = _fmodel.Filetype.regular_file
            try:
                data = zf.open(zinfo.filename)
            except RuntimeError as e:
                if "password required" in e.args[0]:
                    data = None
                    password_needed = True
                else:
                    raise

        if mtime is None:
            try:
                mtime = _datetime(*zinfo.date_time)
            except ValueError:
                mtime = None

        # always add a user_tag, to prevent full duplicate checking when
        # duplicates originate in different archives.
        if password_needed is True:
            user_tag = 'could not extract from file {:d}; password required'.format(fileid)
        else:
            user_tag = 'extracted from file {:d} by archivemodel (zip)'.format(fileid)

        # create the modelitem
        m = db.make_modelitem(_fmodel.MODELNAME, name=fname, path=path,
                              size=size, ftype=ftype, mtime=mtime,
                              atime=atime, ctime=ctime, btime=btime,
                              inode=inode, device=device, uid=uid, gid=gid,
                              deleted=_fmodel.Deleted.intact,
                              data=data, user_tag=user_tag)

        yield m

    for d in _generate_intermediate_dirs(db, dirs_in_filepaths, created_dirs, fileid, device):
        yield d


def _files_from_tar(db, fileobj, fileid):
    ''' yields files from the tar-archive contained in the given file modelitem
    '''

    if fileobj.data is None:
        # nothing to yield
        return

    # make sure we start at the beginning
    if fileobj.data.seekable() is True:
        fileobj.data.seek(0)

    # try if we can open the file as tarfile
    # (will raise exception if not a tarfile)
    tarf = _tarfile.open(fileobj=fileobj.data)

    # intermediate directories do not always have a separate entry
    # so we must produce these ourselve. Keep track of all directory
    # names that are present in the filepaths and keep track of all
    # directories we have already created
    dirs_in_filepaths = set()
    created_dirs = set()

    for membr in tarf:
        # We've seen cases where name and path both contain the (relative) path,
        # let's try to split into filename and pathname
        path, fname = None, None
        if membr.name == membr.path:
            # path and name contain same info, take last component as filename
            path = membr.path
            fname = _os.path.basename(membr.path)
        else:
            # we expect name to contain only toplevel name and no dirname
            p, fname = _os.path.split(membr.name)
            if p != '':
                raise ValueError('unexpected path component in name')

            # and we expect path to contain full path, last component must be filename
            n = _os.path.basename(membr.path)
            if n != '' and n != fname:
                raise ValueError('path and name property disagree on filename')

        # catch other corner-cases here, check if path and name are set
        if fname is None or path is None:
            raise ValueError('path and name parsing problem in tarfile member')

        # Note: this could be simplified similar to zip, but for now kept as is...
        if path.endswith(_os.path.sep):
            # In some archive types (i.e. 7z), the pathname of
            # directories may end with a path separator. In this
            # case, the path and fname will be incorrect, since
            # basename simply performs split operations under the hood.
            # In this case, we expect fname to be ''. Change to
            # the last directory in the path
            if fname != '':
                raise _exceptions.AssumptionBrokenError("expected fname to be empty string here")
            # split by path separator and take the second to last component
            fname = path.split(_os.path.sep)[-2]
            # and strip the trailing slash off from the path
            path = path.rstrip(_os.path.sep)

        # parse the mtime (tar spec says utc):
        # http://www.fileformat.info/format/tar/corion.htm)
        mtime = _datetime.fromtimestamp(membr.mtime, _utc)

        # keep track of the intermediate directories that are needed so we
        # can check if they are all explicitly created.
        # NOTE: this was previously only done for non-directories,
        # but we encountered a zipfile with some empty directories
        # for which the intermediate directories had no separate entries
        # so this was changed both here and in the other files_from... functions
        dirname = _os.path.dirname(path)
        if dirname != '':
            dirs_in_filepaths.add(dirname)

        # we have seen different scenarios here. Sometimes all mode bits are
        # set including the filetype, other times only the permission related
        # bits. So use the convenience functions for getting the filetype
        if membr.isdir():
            # treat dir separately, in order to detect intermediate dirs
            # without tar-entry
            ftype = _fmodel.Filetype.directory
            # make note of the full path of the directory
            created_dirs.add(path)
        elif membr.isblk():
            ftype = _fmodel.Filetype.block_device
        elif membr.ischr():
            ftype = _fmodel.Filetype.character_device
        elif membr.isfile() or membr.islnk():
            # hardlinks are treated as regular files also
            ftype = _fmodel.Filetype.regular_file
        elif membr.issym():
            ftype = _fmodel.Filetype.symbolic_link
        elif membr.isfifo():
            ftype = _fmodel.Filetype.fifo
        else:
            raise ValueError('unable to determine filetype of tarmember')

        # next check with the mode bits
        ftype_bits = _stat.S_IFMT(membr.mode)
        if ftype_bits != 0:
            if ftype != _fmodel._get_filetype(ftype_bits):
                raise ValueError('inconsistency in tarmember filetype determination')

        # other part of mode field contains permissions
        perms = _stat.filemode(membr.mode)

        # make sure linkpath is only set on hardlinks or symlinks
        linkpath = membr.linkname
        if membr.issym() or membr.islnk():
            if linkpath == '':
                raise ValueError('linkpath not set for (sym)link')
        else:
            if linkpath != '':
                raise ValueError('linkpath set for non (sym)link')
            linkpath = None

        # when running the extractfile function on a symbolic link
        # the file-contents of the linktarget is fetched. We have seen
        # at least one occurrence where the linktarget is not part
        # of the tar archive, which will results in a KeyError stating
        # that the linkname is not found. In addition, if the linktarget *is*
        # actually part of the tarfile, we already have this data covered
        # by the regular file. Therefore, set data to None for symbolic links
        if membr.issym():
            data = None
        else:
            data = tarf.extractfile(membr)

        # add user_tag to prevent duplicates from different archives
        # to be treated as such
        user_tag = 'extracted from file {:d} by archivemodel (tar)'.format(fileid)

        # create the modelitem
        m = db.make_modelitem('file', name=fname, path=path,
                              size=membr.size, ftype=ftype, perms=perms,
                              mode=membr.mode, deleted=_fmodel.Deleted.intact,
                              linkpath=linkpath,
                              uid=membr.uid, gid=membr.gid, mtime=mtime,
                              data=data,user_tag=user_tag)
        yield m

    for d in _generate_intermediate_dirs(db, dirs_in_filepaths, created_dirs, fileid):
        yield d


def _get_extract_function(archive_type):
    ''' return the function to be used for extraction '''

    # mapping type to file generation function
    functions = {ArchiveType.Zip: _files_from_zip,
                 ArchiveType.Tar: _files_from_tar,
                 ArchiveType.Cpio: _files_from_libarchive,
                 ArchiveType.SevenZip: _files_from_libarchive}

    if archive_type not in functions:
        raise ValueError("archive_type is not supported")
    return functions[archive_type]


def _extracted_files(db):
    ''' generates file_ids for files that where extracted without error '''

    # get the names for the involved table and columns
    table = db.get_tblname(MODELNAME)
    fileid = db.get_colname(MODELNAME, 'file')
    error = db.get_colname(MODELNAME, 'error')
    contents = db.get_colname(MODELNAME, 'contents')

    # select archives that yielded a fileset and produced no errors
    q = '''SELECT {:s} FROM {:s}
           WHERE {:s} IS NOT null
           AND {:s} IS NULL'''
    q = q.format(fileid, table, contents, error)

    # NOTE: use a dedicated cursor to prevent nesting issues
    results = db.dbcon.cursor().execute(q)

    for restpl in results:
        fileid = restpl[0]
        yield fileid


def _partially_extracted_files(db):
    ''' generate file_ids for files that yielded some fileset and had an error '''

    # get the names for the involved table and columns
    table = db.get_tblname(MODELNAME)
    fileid = db.get_colname(MODELNAME, 'file')
    error = db.get_colname(MODELNAME, 'error')
    contents = db.get_colname(MODELNAME, 'contents')

    # select archives that yielded a fileset and produced an error
    q = '''SELECT {:s} FROM {:s}
           WHERE {:s} IS NOT null
           AND {:s} IS NOT NULL'''
    q = q.format(fileid, table, contents, error)

    # NOTE: use a dedicated cursor to prevent nesting issues
    results = db.dbcon.cursor().execute(q)

    for restpl in results:
        fileid = restpl[0]
        yield fileid


def _parse_extra(data):
    ''' parse a subset of the extra info stored in some zip files '''

    # default values
    mtime, atime, ctime, btime = None, None, None, None
    uid, gid, inode, device = None, None, None, None
    gk = False
    extra_time = None

    # scan over the data in order to find extra field magics
    pos = 0
    maxpos = len(data)-4

    while pos < maxpos:
        # parse the header
        magic, size = _unpack('<HH', data[pos:pos+4])
        # carve out the remaining data for the extra block
        field = data[pos+4:pos+4+size]
        # and update our read position
        pos+=4+size

        if magic == 0x5455:  # UT
            # the specs (extrafld.txt in zip source tree) defines the order of
            # timestamps as: Modification Time, Access Time and Creation Time.
            # This was confirmed by looking at the source of zip version 3.0.
            # However some formats have an extra timestamp, in which case the
            # fourth bit is also set.
            flags = int(field[0])
            offset = 1
            # NOTE: added a boundary check because we have seen
            #       zip files where more than 1 flag was set, but
            #       only a single timestamp was stored
            if flags&1 and offset+4 <= size:
                mtime = _unpack('<I', field[offset:offset+4])[0]
                mtime = _datetime.fromtimestamp(mtime, _utc)
                offset += 4
            if flags&2 and offset+4 <= size:
                atime = _unpack('<I', field[offset:offset+4])[0]
                atime = _datetime.fromtimestamp(atime, _utc)
                offset += 4
            if flags&4 and offset+4 <= size:
                btime = _unpack('<I', field[offset:offset+4])[0]
                btime = _datetime.fromtimestamp(btime, _utc)
                offset += 4
            if flags&8 and offset+4 <= size:
                extra_time = _unpack('<I', field[offset:offset+4])[0]
                extra_time = _datetime.fromtimestamp(extra_time, _utc)
                offset += 4

        elif magic == 0x4e49:   # IN
            inode, device = _unpack("<QI",field)

        elif magic == 0x5855:  # UX
            if size == 8:
                atime, mtime = _unpack("<LL", field)
                atime = _datetime.fromtimestamp(atime, _utc)
                mtime = _datetime.fromtimestamp(mtime, _utc)
            elif size == 12:
                atime, mtime, uid, gid = _unpack("<LLHH", field)
                atime = _datetime.fromtimestamp(atime, _utc)
                mtime = _datetime.fromtimestamp(mtime, _utc)
            else:
                # this should not happen, ignore entry
                pass

        elif magic == 0x7875:  # ux
            version, uidsize = _unpack("<BB", field[0:2])
            # for now ignore other uid/gid sizes
            if uidsize == 4:
                uid, gidsize = _unpack("<IB", field[2:7])
                if uidsize == 4:
                    gid = _unpack("<I", field[7:11])[0]

        elif magic == 0x4b47:  # GK
            gk = True
            version = field[0]
            if version != 1:
                raise ValueError("expected GK version = 1")

        else:
            # ignore other blocks silently. Note that we may miss some
            # interesting properties of extracted files, so when debugging /
            # developing consider uncommenting this error
            # raise ValueError("unsupported extra block encountered: {:}".format(magic))
            pass

    # In this case, the timestamps order of the timestamps is different
    if gk is True:
        ctime = btime
        btime = extra_time

    return (mtime, atime, ctime, btime, uid, gid, inode, device)
