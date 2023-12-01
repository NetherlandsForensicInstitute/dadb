''' stringsmodel.py - models and functions related to strings

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

import multiprocessing as _multiprocessing
import apsw as _apsw
import subprocess as _subprocess
from collections import namedtuple as _nt
import re as _re

from .. import Database as _Database
from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import progresswrapper as _progresswrapper

from . import filemodel as _filemodel
from . import archivemodel as _archivemodel
from . import decompressmodel as _decompressmodel


##########
# MODELS #
##########

# model changelog
# 1 - initial version

MODELNAME = 'strings'
MODELDESCRIPTION = 'strings model for DADB'
MODELVERSION = 1

modeldef = _model_def(MODELNAME,
                     [_field_def('file', _filemodel.modeldef, nullable=False),
                      _field_def('error_sevenbit', str),
                      _field_def('error_le16bit', str),
                      _field_def('sevenbit', str),
                      _field_def('le16bit', str)],
                     MODELDESCRIPTION, MODELVERSION,
                     fail_on_dup=False)


# run at most BLOCKSIZE bytes at a time through strings (default 100MB)
BLOCKSIZE=100*1024*1024

#######
# API #
#######


def register_with_db(db):
    ''' register the models covered by this module '''

    _filemodel.register_with_db(db)
    _archivemodel.register_with_db(db)
    _decompressmodel.register_with_db(db)
    db.register_model(modeldef)


def insert(db, fileid):
    ''' adds the mimetype for the file with the given id to the database.
    '''

    # get the file, or raise exception if model or item does not exist
    f = db.modelitem(_filemodel.MODELNAME, fileid)

    # silently ignore files with no data or non-regular files
    if f.ftype.value != _filemodel.Filetype.regular_file.value:
        return None
    if f.size == 0:
        return None
    if f.data is None:
        return None
    if f.data.stored is False:
        return None

    sevenbit_o, sevenbit_e = _strings(f, encoding='s')
    le16bit_o, le16bit_e = _strings(f, encoding='l')

    m = db.make_modelitem(MODELNAME, file=fileid, error_sevenbit=sevenbit_e,
                          sevenbit=sevenbit_o, error_le16bit=le16bit_e,
                          le16bit=le16bit_o)
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
        counter = (i for i in _progresswrapper(range(len(todolist)), '{:20s}'.format('    strings')))

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

    # insert the results into the database in one transaction
    db.begin_transaction()

    # collect the results in a list
    c = 0
    try:
        for i in range(len(todolist)):
            res = done_queue.get()
            c+=1
            if progress is True:
                next(counter)
            if res is None:
                continue
            m = db.make_modelitem(MODELNAME, file=res[0], sevenbit=res[1],
                                  error_sevenbit=res[2], le16bit=res[3],
                                  error_le16bit=res[4])
            rowid = db.insert_modelitem(m)
    except:
        db.rollback_transaction()
        raise

    db.end_transaction()

    if progress is True:
        # make sure pgoress bar indicates 100% when done :)
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


_searchres = _nt('search_result', 'fileid offset string')


def search_string(db, string, before=0, after=0):
    ''' generate sequence of file, offset, string tuples for given search term '''

    # split into components separated by wildcard
    components = string.split('*')
    # remove empty components (if wildcard is at start or end)
    components = [c for c in components if c != '']
    # create query string
    qstring = '%'.join(components)
    qstring = '%'+qstring+'%'
    # and a regex to search in the matching lines for the exact match
    # NOTE: we use *? to be non-greedy, i.e. yield smallest hits
    regex = _re.compile('.*?'.join(components),flags=_re.I)

    # we use direct queries, so check model existence ourselves
    db.check_registered(MODELNAME)

    q = _string_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (qstring, qstring))

    # Note that each line consists of an offset and the complete string
    # starting at that given offset. This means that the string can contain
    # multiple hits of our search string. So for each result, we need to search
    # for the actual hits within the string as well
    for fileid, sevenbit, le16bit in c:
        if sevenbit is not None:
            for l in sevenbit.splitlines():
                # search for the exact matches in the string
                matches = regex.finditer(l)
                for match in matches:
                    # remove whitespace at start of line
                    pre_len = len(l)
                    l = l.lstrip()
                    post_len = len(l)
                    # determine how many characters where removed
                    removed = pre_len - post_len
                    # split the line in offset and actual string
                    offset, result = l.split(' ', 1)
                    # the offset has a length, which is included in the span
                    offsetlen = len(offset) + 1 + removed
                    # convert offset to int
                    offset = int(offset)
                    # get the start and end of the span
                    start,end = match.span()
                    # compensate the start and end due to presence of offset
                    # string in the line
                    realstart = start-offsetlen
                    realend = end-offsetlen
                    # determine the actual offset by adding line offset and
                    # match offset
                    string_offset = offset + realstart
                    # expand the reported strings based on before and after
                    realend = realend + after
                    realstart = realstart - before
                    if realstart < 0:
                        realstart = 0
                    yield _searchres(fileid, string_offset, result[realstart:realend])

        if le16bit is not None:
            for l in le16bit.splitlines():
                # search for the exact matches in the string
                matches = regex.finditer(l)
                for match in matches:
                    # remove whitespace at start of line
                    pre_len = len(l)
                    l = l.lstrip()
                    post_len = len(l)
                    # determine how many characters where removed
                    removed = pre_len - post_len
                    # split the line in offset and actual string
                    offset, result = l.split(' ', 1)
                    # the offset has a length, which is included in the span
                    offsetlen = len(offset) + 1 + removed
                    # convert offset to int
                    offset = int(offset)
                    # get the start and end of the span
                    start,end = match.span()
                    # compensate the start and end due to presence of offset
                    # string in the line
                    realstart = start-offsetlen
                    realend = end-offsetlen
                    # determine the actual offset by adding line offset and
                    # match offset
                    string_offset = offset + realstart
                    # expand the reported strings based on before and after
                    realend = realend + after
                    realstart = realstart - before
                    if realstart < 0:
                        realstart = 0
                    yield _searchres(fileid, string_offset, result[realstart:realend])


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


def _multiproc_worker(db, input, output):
    ''' determine libmagic for a list of fileids '''

    # make new connection to the database, make sure to only
    # access read-only by not registering the models
    subdb = _Database(db.dbname)
    subdb.load()

    for fileid in iter(input.get, 'STOP'):
        existing = get_by_fileid(subdb, fileid)
        if existing is not None:
            output.put(None)
            continue

        # get the file, or raise exception if model or item does not exist
        f = subdb.modelitem(_filemodel.MODELNAME, fileid)

        # default values
        sevenbit_o = None
        sevenbit_e = None
        le16bit_o = None
        le16bit_e = None

        if f.ftype.value != _filemodel.Filetype.regular_file.value:
            pass
        elif f.data is None:
            pass
        elif f.data.stored is False:
            pass
        else:
            sevenbit_o, sevenbit_e = _strings(f, encoding='s')
            le16bit_o, le16bit_e = _strings(f, encoding='l')

        output.put((fileid, sevenbit_o, sevenbit_e, le16bit_o, le16bit_e))

    # not really needed, since process will be killed, but do it anyway
    subdb.close()
    subdb = None
    # put DONE when STOP is received
    output.put('DONE')


def _strings(f, encoding='s', blocksize=BLOCKSIZE):
    ''' runs blocks from given fileobject through string, recombines output '''

    output = None
    error = None
    char_widths = {'s': 1, 'S': 1, 'b': 2, 'l': 2, 'B': 4, 'L': 4}

    # reset read pointer
    f.data.seek(0)

    if f.size < blocksize:
        # no need to split into blocks
        proc = _subprocess.Popen(['strings', '-e', encoding, '-t', 'd'],
                                 stdin=_subprocess.PIPE, stdout=_subprocess.PIPE,
                                 stderr=_subprocess.PIPE)
        stdout, stderr = proc.communicate(f.data.read())
        if stderr != b'':
            error = stderr.decode()
        if stdout != b'':
            output = stdout.decode()
        return output, error

    # if we get here, we need to process in multiple blocks

    # read first block
    block = f.data.read(blocksize)

    # keep track of where we started from with current strings command
    stringpos = 0
    # collect results in a dictionary mapping offset to string
    results = {}

    while True:

        # update current offset
        readpos = f.data.tell()

        # start strings process
        proc = _subprocess.Popen(['strings', '-e', encoding, '-t', 'd'],
                                 stdin=_subprocess.PIPE, stdout=_subprocess.PIPE,
                                 stderr=_subprocess.PIPE)
        # send the current block
        stdout, stderr = proc.communicate(block)

        # return when error is encountered
        if stderr != b'':
            error = stderr.decode()
            return output, error

        if stdout == b'':
            return output, error

        # due to reading in a block-wise manner, we need to take
        # care not to miss strings that exist on block boundaries:
        #
        #   block 1          block 2          block 3
        # +----------------+----------------+---------------+
        # | string1     string2   string3  string4 string5  |
        # +----------------+----------------+---------------+
        #          ^                     ^
        # so, when reading the next block, we make sure to include
        # bytes from the previous blocks starting at the end of
        # the previously detected string (^) that is fully within the
        # block. In this way, when string2 is first partially
        # added to the results dict, it will be updated during
        # processing of the next block to contain the full string

        last_string_ends = 0
        blocklen = len(block)

        # place results in dictionary
        for l in stdout.splitlines():
            string_offset, string = l.lstrip().split(b' ', 1)
            string_offset = int(string_offset) + stringpos
            string = string.decode()
            results[string_offset] = string
            string_length = char_widths[encoding] * len(string)
            # determine end of last detected string
            string_end = string_offset + string_length
            if string_end < readpos:
                # if the string_end is not on a block_boundary, update
                # position where last detected string ends
                last_string_ends = string_end

        if readpos == f.data.length:
            # we have reached end of data
            break

        # if we get here, we have not yet reached enf of data,
        # seek back to end of last string and read next block
        read_extra = readpos - last_string_ends
        # seek back to end of last string
        f.data.seek(last_string_ends)
        # update the position we need to convert relative offsets to absolute
        stringpos = f.data.tell()
        # read a new block, including the extra bytes between last string and blockboundary
        block = f.data.read(blocksize + read_extra)

    # convert the results to a large string, similar to GNU strings output
    if len(results) != 0:
        output = '\n'.join(['{:7d} {:s}'.format(k, v) for k,v in results.items()])
        # GNU strings places newline at end of file
        output += '\n'

    return output, error


def _unprocessed_file_ids(db):
    ''' generates file_ids that are not yet processed '''

    # no need to run strings on archives and other files that have
    # been decompressed/extracted into one or more output files
    skiplist = set(_archivemodel.processed_file_ids(db))
    skiplist.update(set(_decompressmodel.processed_file_ids(db)))

    # we need primary key from file table and 'file' column from our model table
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
        if fileid not in skiplist:
            yield fileid


_STRING_QUERY = None


def _string_query(db):
    ''' constructs (or fetches from cache) partial query to get item by mimetype '''

    # use cached version if available
    global _STRING_QUERY
    if _STRING_QUERY is not None:
        return _STRING_QUERY

    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    filecol = db.get_colname(MODELNAME, 'file')
    sevenbit = db.get_colname(MODELNAME, 'sevenbit')
    le16bit = db.get_colname(MODELNAME, 'le16bit')

    q = '''SELECT {:s}, {:s}, {:s}
           FROM {:s}
           WHERE {:s} LIKE ? OR {:s} LIKE ?'''

    q = q.format(filecol, sevenbit, le16bit, tbl, sevenbit, le16bit)
    _STRING_QUERY = q
    return _STRING_QUERY
