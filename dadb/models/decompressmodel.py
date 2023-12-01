''' decompressmodel.py - model for decompressing files

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

from enum import Enum as _Enum
import multiprocessing as _multiprocessing
import tempfile as _tempfile
import subprocess as _subprocess
import mmap as _mmap
import os as _os
from collections import namedtuple as _nt

from .. import Database as _Database
from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import progresswrapper as _progresswrapper
from .. import exceptions as _exceptions

from . import filemodel as _fmodel
from . import libmagicmodel as _libmagicmodel
from . import fileparentmodel as _fparentmodel
from . import archivemodel as _archivemodel


#########
# MODEL #
#########

# changelog:
# 1 - initial model version
# 2 - add support for LZ4 compression
# 3 - use external decompression tools instead of Python modules
# 4 - add support for XZ compression
# 5 - add support for LZMA compression

MODELNAME='decompress' # decompress gzipped file (not an archive)
MODELDESCRIPTION='decompress model for DADB'
MODELVERSION = 5


class CompressionType(_Enum):
    ''' type of compression '''

    gzip = 1
    bzip2 = 2
    lz4 = 3
    xz = 4
    lzma = 5


modeldef = _model_def(MODELNAME,
                     [_field_def('file', _fmodel.modeldef, nullable=False),
                      _field_def('outfile', _fmodel.modeldef),
                      _field_def('error', str),
                      _field_def('type_', CompressionType, nullable=False)],
                      MODELDESCRIPTION, MODELVERSION,
                      implicit_dedup=True, fail_on_dup=True)


class DecompressError(_exceptions.DadbError):
    ''' exception thrown when a decompression error occurs '''
    pass


# supported mime-types
mime_types = {'application/gzip' : CompressionType.gzip,
              'application/x-bzip2' : CompressionType.bzip2,
              'application/x-lz4' : CompressionType.lz4,
              'application/x-xz' : CompressionType.xz,
              'application/x-lzma' : CompressionType.lzma}


#######
# API #
#######


def register_with_db(db):
    ''' register the model and its dependencies to the database '''

    _fmodel.register_with_db(db)
    _fparentmodel.register_with_db(db)
    _libmagicmodel.register_with_db(db)
    _archivemodel.register_with_db(db)
    db.register_enum(CompressionType, MODELDESCRIPTION, MODELVERSION)
    db.register_model(modeldef)


def insert(db, fileid):
    ''' decompress the given file if it is a compressed file that is not yet decompressed
    '''

    db.check_registered(MODELNAME)

    # check if the file was already processed
    existing = _entry_by_fileid(db, fileid)
    if existing is not None:
        return existing

    # then check if the file was already processed as an archive without error,
    # since some compressed files are also an archive (i.e. tgz) and if the file is
    # already processed as archive, there is no need to decompress
    archive_item = _archivemodel.get_by_fileid(db, fileid)
    if archive_item is not None:
        if archive_item.error is None and archive_item.contents is not None:
            return None

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

    # make sure everything happens in a single transaction
    started_transaction = db.begin_transaction()

    # determine the libmagic (if not already determined)
    try:
        _libmagicmodel.insert(db, fileid)
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    # get the libmagic value and determine compression type
    filemagic = _libmagicmodel.get_by_fileid(db, fileid)
    compression_type = mime_types.get(filemagic.mimetype)

    # Not a known compressed file, return None
    if compression_type is None:
        if started_transaction is True:
            db.end_transaction()
        return None

    # disable duplicate checking, since we have already checked if the file has
    # been processed. Also the decompressed file should be unique due to the
    # fact that we add a unique user_tag to it.
    db.disable_duplicate_checking(_fmodel.MODELNAME)
    db.disable_duplicate_checking(_fparentmodel.MODELNAME)

    try:
        # get the parameters for the tool runner based on compression_type
        tool_params = _get_parameters(compression_type, f.name)
        # attempt to decompress the file data, get the name of the tempfile
        outname = _tool_runner(f.data, tool_params)
        # a user tag to make the file unique
        user_tag = 'extracted from file {:d} by decompressmodel{:s}'.format(fileid, tool_params.tag_suffix)
        # create the filemodel item for the decompressed file
        decompressed_file = _make_outfile(db, f, tool_params.newname, outname, user_tag)
        # insert the file modelitem for the decompressed file
        outfile_id = db.insert_modelitem(decompressed_file)
        # insert the relation between the compressed and decompressed file
        _fparentmodel.insert(db, outfile_id, fileid, skip_checks=True)
        # create and insert the compression model item
        m = db.make_modelitem(MODELNAME, file=fileid, outfile=outfile_id, error=None, type_=compression_type)
        rowid = db.insert_modelitem(m)

    except Exception as e:
        # some error occurred during extraction, insert compression model item
        # with the error that occurred
        m = db.make_modelitem(MODELNAME, file=fileid, outfile=None, error=repr(e), type_=compression_type)
        rowid = db.insert_modelitem(m)

    finally:
        # enable duplicate checking again always!
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)
        # and end the transaction if we started it
        if started_transaction is True:
            db.end_transaction()

    return rowid


def update(db, progress=False, maxrounds=5, multiprocess=True):
    ''' decompress unprocessed files

    Maxrounds limits the total number of 'rounds' that is used to find new
    compressed files (i.e. double compressed files), defaults to 5 rounds '''

    db.check_registered(MODELNAME)

    round_ = 0
    while round_ < maxrounds:
        # run libmagic over the file model items
        # libmagicmodel.update manages it's own transaction and makes sure no
        # transaction is active when the function returns
        _libmagicmodel.update(db, progress)

        # keep track of processed files
        c = 0

        # try to extract new archives
        if multiprocess is True:
            c += _multiprocess_decompress_round(db, progress)
        else:
            c += _decompress_round(db, progress)

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


def processed_file_ids(db):
    ''' yield fileids of files that are decompressed without errors '''

    for fid in _decompressed_file_ids(db):
        yield fid


def drop_original_file_data(db, decompress_id):
    ''' drop the blocks of the original file if the decompression was successful '''

    m = get(db, decompress_id)
    if m.error is not None:
        raise ValueError("decompression had an error, can not drop data via this function")
    if m.outfile is None:
        raise ValueError("decompression produced no outfile, can not drop data via this function")

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

    the default minsize of 0 causes *all* original files to be dropped, change
    to a higher value if you want to keep the data of small compressed files
    '''

    started_transaction = db.begin_transaction()
    try:
        for fileid in _decompressed_file_ids(db):
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


def _decompress_round(db, progress=False):
    ''' process unprocessed gzipped files '''

    # get a list of all unprocessed files
    todolist = list(_unprocessed_file_ids(db))

    if len(todolist) == 0:
        return 0

    if progress is True:
        todolist = _progresswrapper(todolist, '{:20s}'.format('    decompress'))

    c = 0

    # disable duplicate checking
    db.disable_duplicate_checking(_fmodel.MODELNAME)
    db.disable_duplicate_checking(_fparentmodel.MODELNAME)

    # perform each round in a transaction, as to prevent rolling
    # back all rounds, when error occurs in last round
    db.begin_transaction()

    try:
        for id_ in todolist:
            rowid = insert(db, id_)
            if rowid != None:
                c+=1

    except:
        db.rollback_transaction()
        raise

    finally:
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)

    db.end_transaction()

    return c


def _make_outfile(db, f, newname, outname, user_tag):
    ''' create a file model item for the generated output file '''

    # open the output file as mmapped files
    with open(outname, 'rb') as outfile:
        outfile.seek(0, 2)
        size = outfile.tell()
        if size == 0:
            # we have seen some cases where the decompressed file has size 0
            # which caused the mmap to fail. Instead use None for data object.
            outfile = None
            _os.unlink(outname)
        else:
            outfile.seek(0)
            # memory map the output file so we can add the mmapped item to the file
            outfile = _mmap.mmap(outfile.fileno(), size, access=_mmap.ACCESS_READ)
            # unlink tmpfile so that it is removed once the mmapped object is released
            _os.unlink(outname)

    # make and return the model item
    # NOTE: path is also set to newname, since the file is not really on a 
    #       filesystem and we don't want to suggest otherwise by adding path
    #       components
    # NOTE: this will already add the data object to the database
    m = db.make_modelitem(_fmodel.MODELNAME, atime=f.atime, btime=f.btime, ctime=f.ctime,
                          data = outfile, deleted=f.deleted, dtime=f.dtime,
                          ftype = f.ftype, gid=f.gid, inode=f.inode,
                          device=f.device, linkpath=f.linkpath,
                          mode=f.mode, mtime=f.mtime, name=newname, nlinks=f.nlinks, path=newname,
                          perms=f.perms, size=size, uid=f.uid, user_tag=user_tag)

    return m


def _get_parameters(compression_type, filename):
    ''' return the required parameters for running the decompress tool '''

    tool_params = _nt('tool_parameters', 'in_suffix out_suffix command_list '
                                         'outfile tag_suffix newname')

    if compression_type == CompressionType.gzip:
        in_suffix = ".gz"
        out_suffix = ""
        command_list = ['gunzip', '-d', '-q', '-k']
        outfile = False
        tag_suffix = ' (gzip)'
        if filename.endswith('.gz'):
            newname = filename[:-3]
        elif filename.endswith('.gzip'):
            newname = filename[:-5]
        elif filename.endswith('.tgz'):
            newname = filename[:-4]+'.tar'
        else:
            newname = filename+'[gzip_unpacked]'

    elif compression_type == CompressionType.bzip2:
        in_suffix = ".bz2"
        out_suffix = ""
        command_list = ['bzip2', '-d', '-q', '-k']
        outfile = False
        tag_suffix = ' (bunzip2)'
        if filename.endswith('.bz2'):
            newname = filename[:-4]
        elif filename.endswith('.bz'):
            newname = filename[:-3]
        else:
            newname = filename+'[bzip2_unpacked]'

    elif compression_type == CompressionType.lz4:
        in_suffix = ".lz4"
        out_suffix = ".out"
        command_list = ['lz4', '-q', '-d']
        outfile = True
        tag_suffix = ' (lz4)'
        if filename.endswith('.lz4'):
            newname = filename[:-4]
        else:
            newname = filename+'[lz4_unpacked]'

    elif compression_type == CompressionType.xz:
        in_suffix = ".xz"
        out_suffix = ""
        command_list = ['xz', '-d', '-q', '-k']
        outfile = False
        tag_suffix = ' (xz)'
        if filename.endswith('.xz'):
            newname = filename[:-3]
        else:
            newname = filename+'[xz_unpacked]'

    elif compression_type == CompressionType.lzma:
        in_suffix = ".lzma"
        out_suffix = ""
        command_list = ['lzma', '-d', '-q', '-k']
        outfile = False
        tag_suffix = ' (lzma)'
        if filename.endswith('.lzma'):
            newname = filename[:-5]
        else:
            newname = filename+'[lzma_unpacked]'

    else:
        raise DecompressError("compression_type unknown")

    return tool_params(in_suffix, out_suffix, command_list, 
                       outfile, tag_suffix, newname)


def _tool_runner(input_data, params):
    ''' call external tool via subprocess on given input_data

    Arguments:
    input_data   : a file like object with the input data
    params       : named tuple with parameters as returned by _get_parameters

    Returns

    outname      : name of temporary output file produced by the tool
    '''

    command_list = [c for c in params.command_list]

    with _tempfile.NamedTemporaryFile(suffix=params.in_suffix, delete=False) as infile:
        # copy the data into a tempfile
        input_data.seek(0)
        infile.file.write(input_data.read())
        # make sure all bytes are flushed by closing the file (delete = False!)
        infile.close()

        # determine the filename of the temporary output file
        outname = infile.name[:-len(params.in_suffix)] + params.out_suffix

        if infile.name == outname:
            _os.unlink(infile.name)
            raise ValueError("name of input and output tempfiles is equal, provide suffix!")

        command_list.append(infile.name)
        if params.outfile is True:
            command_list.append(outname)

        try:
            proc = _subprocess.Popen(command_list, stdout=_subprocess.PIPE,
                                     stderr=_subprocess.PIPE)
            stdout = [l.decode().rstrip() for l in proc.stdout]
            stderr = [l.decode().rstrip() for l in proc.stderr]
        finally:
            # make sure we cleanup the input file
            _os.unlink(infile.name)

        if stdout != [] or stderr != []:
            try:
                # attempt to unlink output file if it exists
                _os.unlink(outname)
            except FileNotFoundError:
                pass
            # raise a DecompressError with the output from stderr
            raise DecompressError(' '.join(stderr))

        return outname


def _unprocessed_file_ids(db):
    ''' generates file_ids that have not yet been decompressed '''

    # due to the overlap in mime-type for some archives (i.e. tar / gzip), we need to
    # check if a file has already been successfully extracted as archive. So collect
    # extracted archives in a set first
    extracted_archives = set(_archivemodel.processed_file_ids(db))

    # collect all mimetypes from the mime_types dictionary
    all_mimes = [k for k in mime_types.keys()]
    # prepare mimetype query
    libmagictable = db.get_tblname(_libmagicmodel.MODELNAME)
    mimetype = db.get_colname(_libmagicmodel.MODELNAME, 'mimetype')
    fileid = db.get_colname(_libmagicmodel.MODELNAME, 'file')
    where = ' OR '.join(['{:s}.{:s} == "{:s}"'.format(libmagictable, mimetype, t) for t in all_mimes])
    candidates = 'SELECT {:s}.{:s} FROM {:s} WHERE ({:s})'.format(libmagictable, fileid, libmagictable, where)

    # and we need only those files that are not already decompressed
    my_table = db.get_tblname(MODELNAME)
    my_fileid = db.get_colname(MODELNAME, 'file')
    processed_files = 'SELECT {:s}.{:s} FROM {:s}'.format(my_table, my_fileid, my_table)

    # select those files which have no entry in mimetype table
    q = '''{:s} AND ({:s}.{:s} NOT IN ({:s}))'''
    q = q.format(candidates, libmagictable, fileid, processed_files)

    # NOTE: use a dedicated cursor to prevent nesting issues
    results = db.dbcon.cursor().execute(q)

    for restpl in results:
        fileid = restpl[0]
        if fileid in extracted_archives:
            # already extracted as archive, skip
            continue
        else:
            yield fileid


def _decompressed_file_ids(db):
    ''' generate file ids of successfully decompressed files '''

    # and we need only those files that are not already decompressed
    my_table = db.get_tblname(MODELNAME)
    fileid = db.get_colname(MODELNAME, 'file')
    outfileid = db.get_colname(MODELNAME, 'outfile')
    error = db.get_colname(MODELNAME, 'error')
    q = 'SELECT {:s} FROM {:s} WHERE {:s} IS NOT NULL AND {:s} IS NULL'.format(fileid, my_table, outfileid, error)

    results = db.dbcon.cursor().execute(q)
    for restpl in results:
        fileid = restpl[0]
        yield fileid


################
# multiprocess #
################


# NOTE: this seems to work okay, but the speedup depends largely on the input
# data, because in the end, all data has to be inserted by a single process due
# to the nature of SQLite. Importing data involves hashing within this main
# process, which seems to be the largest factor for making this CPU-bound and
# not I/O bound. So if there are some small files and one large file to
# decompress, speedup will be minimal. If there are many files to decompress
# that are not too large, we should get some speedup by using multiprocessing.


def _multiproc_worker(db, input, output):
    ''' decompress files in input queue place results on output queue '''

    # make new connection to the database, make sure to only
    # access read-only by not registering the models
    subdb = _Database(db.dbname)
    subdb.load()

    for fileid in iter(input.get, 'STOP'):

        # No need to check for existing, this is called from update
        # function and such items are not in the TODO list.

        # determine the type of compression and get the decompress function
        filemagic = _libmagicmodel.get_by_fileid(subdb, fileid)
        compression_type = mime_types.get(filemagic.mimetype)

        # get the file
        f = subdb.modelitem(_fmodel.MODELNAME, fileid)

        # attempt decompression
        try:

            # get the parameters for the tool runner based on compression_type
            tool_params = _get_parameters(compression_type, f.name)
            tag_suffix = tool_params.tag_suffix
            newname = tool_params.newname
            # attempt to decompress the file data, get the name of the tempfile
            # with the decompressed data
            outname = _tool_runner(f.data, tool_params)
            # if we get here, no error was raised
            error = None

        except Exception as e:
            error = repr(e)
            outname = None
            tag_suffix = ''
            newname = None

        user_tag = 'extracted from file {:d} by decompressmodel{:s}'.format(fileid, tag_suffix)

        output.put((fileid, user_tag, newname, outname, error, compression_type))

    # not really needed, since process will be killed, but do it anyway
    subdb.close()
    subdb = None
    # put DONE when STOP is received
    output.put('DONE')


def _multiprocess_decompress_round(db, progress=False):
    ''' determine mimetype for *regular* files for which mimetype was not yet known '''

    # use all the cores minus 1
    processes = _multiprocessing.cpu_count() - 1

    # collect the todolist
    todolist = list(_unprocessed_file_ids(db))

    if len(todolist) == 0:
        return 0

    if progress is True:
        # create a fake sequence wrapped in progresswrapper
        counter = (i for i in _progresswrapper(range(len(todolist)), '{:20s}'.format('    decompress')))

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

    # disable duplicate checking
    db.disable_duplicate_checking(_fmodel.MODELNAME)
    db.disable_duplicate_checking(_fparentmodel.MODELNAME)

    # perform each round in a transaction, as to prevent rolling
    # back all rounds, when error occurs in last round
    db.begin_transaction()

    # collect the results in a list
    c = 0
    try:
        for i in range(len(todolist)):
            res = done_queue.get()
            c+=1
            if progress is True:
                next(counter)
            # extract the values in the result
            fileid, user_tag, newname, outname, error, compression_type = res
            # use fileid to get the compressed file
            f = _fmodel.get(db, fileid)

            # If an error occurred, add a decompression model item with the
            # error and continue to next item on the result queue
            if error is not None:
                m = db.make_modelitem(MODELNAME, file=fileid, outfile=None, error=error, type_=compression_type)
                rowid = db.insert_modelitem(m)
                continue

            # create and insert the filemodel item for the decompressed file
            decompressed_file = _make_outfile(db, f, newname, outname, user_tag)
            outfile_id = db.insert_modelitem(decompressed_file)
            # insert the relation between the compressed and decompressed file
            _fparentmodel.insert(db, outfile_id, fileid, skip_checks=True)
            # create and insert the compression model item
            m = db.make_modelitem(MODELNAME, file=fileid, outfile=outfile_id, error=error, type_=compression_type)
            rowid = db.insert_modelitem(m)

    except:
        db.rollback_transaction()
        raise

    finally:
        db.enable_duplicate_checking(_fmodel.MODELNAME)
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)

    db.end_transaction()

    if progress is True:
        # make sure progresswrapper is finished
        list(counter)

    if c != len(todolist):
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

    return c
