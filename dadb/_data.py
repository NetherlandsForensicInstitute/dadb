''' data.py - class for reading data items stored in DADB databases

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

from io import IOBase as _IOBase
from io import BytesIO as _BytesIO
from io import UnsupportedOperation as _UnsupportedOperation
from apsw import SQLError as _SQLError
import hashlib as _hashlib
from mmap import mmap as _mmap

from ._exceptions import NoSuchDataObjectError as _NoSuchDataObjectError

# WARNING: changes to data and block schema require changes here as well!

# Data is stored in block records. This configuration variable defines the
# max blocksize for a single data block. Large blocks reduce the overhead
# (less queries required for fetching or creating a data object), but also
# may lead to larger databases, due to less posibilities for de-duplication.

# NOTE: we may choose smaller blocksizes which gives us a higher change at a
# smaller database file (if there are many duplicate blocks) at the
# expense of performance. A sane value seems to be 128K (see:
# https://eklitzke.org/efficient-file-copying-on-linux), which gives us less
# de-duplication posibilities, but arguably more (write) performance.

# NOTE: Setting to 1GB leads to errors on my system, such as:
# Error binding parameter 0 - probably unsupported type

#MAXBLOCKSIZE = 131072       # 128KB
MAXBLOCKSIZE = 8388608       #   8MB

# Size of the read-ahead cache
CACHESIZE = MAXBLOCKSIZE  # keep a cache of a single blocksize
                          # to prevent reading the same block over and over
                          # when accessing small distinct parts of a block

# max number of blocks to keep in memory when inserting a data object
MAXCACHEDBLOCKS = int(536870912/MAXBLOCKSIZE)  # 512MB


class DataInserter():
    ''' Class responsible for inserting Data objects into a DADB database

    This class exists to prevent doing some common stuff for each insertion,
    such as query building, which depends on the database prefix. A Database
    should have a single DataInserter '''

    def __init__(s, prefix):
        ''' initialize the DataInserter '''

        q = 'INSERT INTO {:}block({:}sha1, {:}size, {:}data) VALUES (?, ?, ?)'
        s.insert_block_query = q.format(prefix, prefix, prefix, prefix)

        # insert data
        q = 'INSERT INTO {:s}data({:s}md5, {:s}sha1, {:s}sha256, {:s}size, {:s}stored) VALUES (?,?,?,?,1)'
        s.insert_data_query = q.format(*(prefix,)*6)

        # insert unstored data
        q = 'INSERT INTO {:s}data({:s}md5, {:s}sha1, {:s}sha256, {:s}size, {:s}stored) VALUES (?,?,?,?, 0)'
        s.insert_unstored_data_query = q.format(*(prefix,)*6)

        # insert blockmap entries
        q = 'INSERT INTO {:s}blockmap VALUES (?, ?, ?)'
        s.insert_blockmap_query = q.format(prefix)


    def insert_block(s, block, dbcon, cursor):
        ''' inserts the given block of data (bytes) into the block table '''

        # compute sha1 for this block
        h = _hashlib.sha1()
        h.update(block)
        sha1 = h.hexdigest()

        # NOTE: we do no longer apply deduplication here, this is performed at
        # 'data' separately with a deduplication routine. Rationale: keeping
        # an index on the sha1 column requires too much space (during transaction)
        # and querying sha1 without such an index takes way too long.

        # NOTE: an alternative to using this custom block approach is to
        # use apsw Blob I/O for storing the entire Data object, however we
        # want to be able to deduplicate at the block level. Blob I/O was
        # tested as an alternative for adding a single block as well, but this
        # gives the same result as performing a simple insert with all bytes
        # of the given block. I see no benefit in using Blob I/O over simply
        # adding the bytes in one go.

        cursor.execute(s.insert_block_query, (sha1, len(block), block))
        rowid = dbcon.last_insert_rowid()
        return rowid


    def insert_unstored_data(s, dbcon, fileobj, offset=0, length=None):
        ''' Adds an entry in the data table, without actually storing any data blocks.
        This can be useful for storing metadata about large binary objects for which
        it is not required to store the actual data '''

        if fileobj is None:
            return None

        if hasattr(fileobj, '_dataid'):
            if offset == 0 and length is None:
                # this is already a dataobject, and no slice is requested
                return fileobj._dataid

        if not hasattr(fileobj, 'read'):
            raise ValueError('need a readable file-like-object')
        if fileobj.closed is True:
            raise ValueError('need a file-like-object that is not closed')

        # reset position, if fileobj is seekable, otherwise assume correct position!
        if isinstance(fileobj, _mmap):
            fileobj.seek(offset)
        elif fileobj.seekable() is True:
            fileobj.seek(offset)
        elif offset != 0:
            raise ValueError('cannot give offset for non-seekable fileobj')

        # to prevent complexities, use a dedicated cursor
        cursor = dbcon.cursor()
        # start a transaction, if we are not already inside one
        started_transaction = False
        try:
            cursor.execute('BEGIN TRANSACTION')
            started_transaction = True
        except _SQLError as e:
            if e.args[0] == 'SQLError: cannot start a transaction within a transaction':
                # we did not start a transaction
                pass
            else:
                raise

        # create hashobjects
        hashers = [_hashlib.md5(), _hashlib.sha1(), _hashlib.sha256()]

        # keep track of overall size
        total_size = 0

        # read first block and store offset (0)
        if length is not None:
            if length < MAXBLOCKSIZE:
                block = fileobj.read(length)
                length = 0
            else:
                block = fileobj.read(MAXBLOCKSIZE)
                length = length - MAXBLOCKSIZE
        else:
            block = fileobj.read(MAXBLOCKSIZE)

        total_size += len(block)

        # if the first block is empty, assume entire file is empty
        if len(block) == 0:
            if started_transaction is True:
                cursor.execute('COMMIT')
            return None

        # blocklist for storing (offset, blockhash) tuples
        blocklist = []

        while block:

            # update the hashobjects for the entire data entry
            [h.update(block) for h in hashers]

            # and read next block
            if length is not None:
                if length < MAXBLOCKSIZE:
                    block = fileobj.read(length)
                    length = 0
                else:
                    block = fileobj.read(MAXBLOCKSIZE)
                    length = length - MAXBLOCKSIZE
            else:
                block = fileobj.read(MAXBLOCKSIZE)

            total_size += len(block)

        # finalize the hashes
        md5, sha1, sha256 = [h.hexdigest() for h in hashers]

        # store the metadata on this data object
        cursor.execute(s.insert_unstored_data_query, (md5, sha1, sha256, total_size))
        rowid = dbcon.last_insert_rowid()

        if started_transaction is True:
            cursor.execute('COMMIT')

        return rowid


    def insert_data(s, dbcon, fileobj, offset=0, length=None):
        ''' stores the data in the given fileobject into the database. returns the
        rowid of the corresponding data record. If offset and/or length are given,
        a slice of the given fileobject data is inserted. The hashes md5, sha1 and
        sha256 are calculated on the fly.

        Note: if the fileobj is not seekable, the caller must make sure the
        current position is correct. Otherwise, we seek to offset 0 before
        insert.
        '''

        if fileobj is None:
            return None

        if hasattr(fileobj, '_dataid'):
            if offset == 0 and length is None:
                # this is already a dataobject, and no slice is requested
                return fileobj._dataid

        if not hasattr(fileobj, 'read'):
            raise ValueError('need a readable file-like-object')
        if fileobj.closed is True:
            raise ValueError('need a file-like-object that is not closed')

        # reset position, if fileobj is seekable, otherwise assume correct position!
        if isinstance(fileobj, _mmap):
            fileobj.seek(offset)
        elif fileobj.seekable() is True:
            fileobj.seek(offset)
        elif offset != 0:
            raise ValueError('cannot give offset for non-seekable fileobj')

        # to prevent complexities, use a dedicated cursor
        cursor = dbcon.cursor()

        # start a transaction, if we are not already inside one
        started_transaction = False
        try:
            cursor.execute('BEGIN TRANSACTION')
            started_transaction = True
        except _SQLError as e:
            if e.args[0] == 'SQLError: cannot start a transaction within a transaction':
                # we did not start a transaction
                pass
            else:
                raise

        # create hashobjects
        hashers = [_hashlib.md5(), _hashlib.sha1(), _hashlib.sha256()]

        # keep track of overall size
        total_size = 0

        # read first block and store offset (0)
        if length is not None:
            if length < MAXBLOCKSIZE:
                block = fileobj.read(length)
                length = 0
            else:
                block = fileobj.read(MAXBLOCKSIZE)
                length = length - MAXBLOCKSIZE
        else:
            block = fileobj.read(MAXBLOCKSIZE)

        total_size += len(block)

        # offset in destination
        d_offset = 0

        # if the first block is empty, assume entire file is empty
        if len(block) == 0:
            if started_transaction is True:
                cursor.execute('COMMIT')
            return None

        blockcache = []
        cachedblocks = 0
        cache_was_full = False

        # blocklist for storing (offset, blockhash) tuples
        blocklist = []

        while block:

            # update the hashobjects for the entire data entry
            [h.update(block) for h in hashers]
            # place the block in the block cache
            blockcache.append((d_offset, block))
            cachedblocks += 1

            # update offset with current block length
            d_offset += len(block)
            # and read next block

            if length is not None:
                if length < MAXBLOCKSIZE:
                    block = fileobj.read(length)
                    length = 0
                else:
                    block = fileobj.read(MAXBLOCKSIZE)
                    length = length - MAXBLOCKSIZE
            else:
                block = fileobj.read(MAXBLOCKSIZE)

            total_size += len(block)

            if cachedblocks == MAXCACHEDBLOCKS:
                # flush the blockcache into the database
                cache_was_full = True
                for off, blk in blockcache:
                    # insert the block and store offset, blockid tuple
                    bid = s.insert_block(blk, dbcon, cursor)
                    blocklist.append((off, bid))
                blockcache = []
                cachedblocks = 0

        # finalize the hashes
        md5, sha1, sha256 = [h.hexdigest() for h in hashers]

        # write (remaining) blocks
        for off, blk in blockcache:
            bid = s.insert_block(blk, dbcon, cursor)
            blocklist.append((off, bid))

        # store the metadata on this data object
        cursor.execute(s.insert_data_query, (md5, sha1, sha256, total_size))
        rowid = dbcon.last_insert_rowid()

        # and fill the blockmap table with one entry per block
        for b_offset, blkid in blocklist:
            cursor.execute(s.insert_blockmap_query, (rowid, blkid, b_offset))

        if started_transaction is True:
            cursor.execute('COMMIT')

        return rowid


class DataManager():
    ''' Class responsible for dealing with Data objects in a DADB database

    This class exists to prevent doing some common stuff multiple times,
    such as query building, which depends on the database prefix. A Database
    should have a single DataManager '''


    def __init__(s, prefix):
        ''' initialize the DataManager '''

        # query to get the hashes and whether data is actually stored
        q = 'SELECT {:s}md5, {:s}sha1, {:s}sha256, {:s}size, {:s}stored ' +\
            'FROM {:s}data WHERE {:s}id == ?'
        s.meta_query = q.format(*(prefix,)*7)

        # query for selecting blocks for a specific range
        q = 'SELECT {:}offset, {:}blkid, {:}size, {:}data ' +\
            'FROM {:}blockmap JOIN {:}block ON {:}blkid = {:}block.{:}id ' +\
            'WHERE {:}dataid IS ? AND ? - {:}size < {:}offset AND ? > {:}offset;'
        s.block_query = q.format(*(prefix,)*13)

        # query to determine the size
        q = 'SELECT {:}offset+{:}size FROM {:}blockmap JOIN {:}block ' +\
            'ON {:}blkid = {:}block.{:}id WHERE {:}dataid = ? ' +\
            'ORDER BY {:}offset DESC LIMIT 1;'
        s.size_query = q.format(*(prefix,)*9)

        # query to delete blocks that are associated with the data object,
        # which do not occur in any of the other data objects
        q = 'DELETE FROM {:s}block WHERE {:s}id in (SELECT {:s}blkid ' +\
            'FROM (SELECT {:s}blkid,count(*) as cnt FROM {:s}blockmap ' +\
            'WHERE {:s}blkid IN (SELECT {:s}blkid FROM {:s}blockmap ' +\
            'WHERE {:s}dataid == ?) GROUP BY {:s}blkid) WHERE cnt == 1);'
        s.blkdel_query = q.format(*(prefix,)*10)

        # query to delete blockmap entries
        q = 'DELETE FROM {:s}blockmap WHERE {:s}dataid == ?'
        s.blkmapdel_query = q.format(prefix, prefix)

        # query to update data record
        q = 'UPDATE {:s}data SET {:s}stored=0 WHERE {:s}id == ?'
        s.unstore_query = q.format(prefix, prefix, prefix)

        # query to fetch data by sha256
        q = 'SELECT rowid from {:s}data where {:s}sha256 is ?'
        s.sha256query = q.format(prefix, prefix)

        # query to select blocks with duplicate hashes
        q = 'SELECT {:}block.{:}id,{:}block.{:}sha1 FROM {:}block ' +\
            'WHERE {:}block.{:}sha1 IN (SELECT {:}block.{:}sha1 ' +\
            'FROM {:}block GROUP BY {:}block.{:}sha1 ' +\
            'HAVING COUNT(*) > 1) ORDER BY {:}sha1;'
        s.duplicate_block_query = q.format(*(prefix,)*13)

        # query to update blkid of blockmap entry
        q = 'UPDATE {:}blockmap SET {:}blkid = ? WHERE {:}blkid IS ?'
        s.update_blockmap_query = q.format(*(prefix,)*3)

        # query to remove block from block table
        q = 'DELETE FROM {:s}block WHERE {:s}id == ?'
        s.delete_block_query = q.format(prefix, prefix)

        # query to create an index on the blockmap table
        q = 'CREATE INDEX IF NOT EXISTS tmpblkidx ON {:}blockmap ({:}blkid);'
        s.make_blockmap_idx_query = q.format(prefix, prefix)

        # query to drop blockmap table index
        s.drop_blockmap_idx_query = 'DROP INDEX tmpblkidx'

        # query to find orphan blocks
        q = 'SELECT {:s}id FROM {:s}block WHERE {:s}id NOT IN ' +\
            '(SELECT {:s}blkid FROM {:s}blockmap);'
        s.orphan_blocks_query = q.format(*(prefix,)*5)


    def get_data(s, dbcon, id_):
        ''' returns the data in the data table with the given id as Data object '''

        if id_ is None:
            return None
        try:
            d = Data(s, dbcon, id_)
        except StopIteration:
            raise _NoSuchDataObjectError('Data object with given id not available')
        return d


    def data_by_sha256(s, sha256, cursor):
        ''' returns rowids of data objects with the given sha256 '''

        cursor.execute(s.sha256query, (sha256,))
        res = [r[0] for r in cursor]
        return res


    def duplicate_blocks(s, cursor):
        ''' generates sequence of duplicate blocks by sha1

        Yields tuples (sha1, blocklist) for each sha1 where len(blocklist) > 1
        '''

        cursor.execute(s.duplicate_block_query)

        curhash = None
        curblks = []
        for blkid, sha1 in cursor:
            if curhash is None:
                # first iteration only
                curhash = sha1
                curblks.append(blkid)
            elif curhash != sha1:
                yield curhash, curblks
                curhash = sha1
                curblks = [blkid]
            else:
                curblks.append(blkid)

        if curhash is None:
            # nothing left to yield
            return

        yield curhash, curblks


    def remove_duplicate_blocks(s, duplicates, cursor):
        ''' removes duplicate blocks and update blockmap accordingly

        Note that this goes a lot faster with an index in place,
        which is why this function should not be called directly.
        Instead, the function with the same name of the database object
        should be called.
        '''

        if len(duplicates) == 0:
            # we are done if there are no duplicate blocks
            return

        for sha1, blocklist in duplicates:
            keepblock = None
            for blk in blocklist:
                # a bit awkward, but if blocklist is large, a slice is expensive
                # so instead we store the first block during the iteration
                if keepblock is None:
                    keepblock = blk
                    continue
                # update the blockmap to point to keepblock
                cursor.execute(s.update_blockmap_query, (keepblock, blk))
                # remove the original block
                cursor.execute(s.delete_block_query, (blk,))


    def _orphan_blocks(s, cursor):
        ''' yields blockids of blocks with no data object attached to it

        When deletion of blocks is done properly, this should never yield
        any blkids, but just in case provide a function for checking this
        '''

        cursor.execute(s.orphan_blocks_query)
        for r in cursor:
            yield r[0]


    def _remove_orphan_blocks(s, select_cursor, update_cursor):
        ''' remove orphan blocks '''

        # start a new transaction, making sure a transaction was not yet active
        try:
            update_cursor.execute('BEGIN TRANSACTION')
        except _SQLError as e:
            if e.args[0] == 'SQLError: cannot start a transaction within a transaction':
                raise RuntimeError("delete_orphan_blocks should not be part of some other transaction")
            else:
                raise

        for blk in s.orphan_blocks(select_cursor):
            update_cursor.execute(s.delete_block_query, (blk,))

        update_cursor.execute('COMMIT')


class Data(_IOBase):
    ''' class to access data as file-like-object '''


    def __init__(s, data_manager, dbcon, dataid):
        ''' initialize Data object '''

        # we use this class only for reading data, use dedicated cursor
        # for each active Data object
        s._cursor = dbcon.cursor()
        s._connection = dbcon
        s._dataid = dataid
        s._data_manager = data_manager

        # fetch hashes and if blocks are stored
        r = s._cursor.execute(s._data_manager.meta_query, (s._dataid,))
        s.md5, s.sha1, s.sha256, s.length, s.stored = next(r)
        s.stored=bool(s.stored)

        # set position to 0
        s._pos = 0

        # sequential access is rather quick, but when a lot of seeks are used,
        # this can become slow, so once reading starts, maintain a cache around
        # readpos
        s._cache_start = 0
        s._cache_end = 0
        s._cache = None

        super().__init__()


    def close(s):
        ''' close read access to this data object '''
        # close the db cursor and connection
        s._cursor.close()
        super().close()


    def fileno(s):
        ''' unsupported '''
        raise _UnsupportedOperation("fileno")


    def flush(s):
        ''' does nothing '''
        return None


    def isatty():
        ''' returns False '''
        return False


    def drop_blocks(s):
        ''' removes the blocks associated with a data object, keeping the data
        record intact (and setting 'stored' to 0). '''

        # use a dedicated cursor for this
        c = s._connection.cursor()

        # perform this inside a transaction, if not yet inside one
        started_transaction = False
        try:
            c.execute('BEGIN TRANSACTION')
            started_transaction = True
        except _SQLError:
            pass

        c.execute(s._data_manager.blkdel_query, (s._dataid,))
        c.execute(s._data_manager.blkmapdel_query, (s._dataid,))
        c.execute(s._data_manager.unstore_query, (s._dataid,))

        if started_transaction is True:
            c.execute('COMMIT')

        # we sometimes see after a call to drop_blocks that we can not perform
        # a vacuum operation with the following error message:
        # apsw.SQLError: SQLError: cannot VACUUM - SQL statement in progress
        # this might be caused by the active cursor we created here. Try to
        # prevent this by releasing the variable and freeing/releasing the cursor.
        c = None

        # set stored state to false
        s.stored=False


    def read(s, size=-1, debug=False):
        ''' read 'size' bytes '''

        if s.stored is False:
            raise IOError('data is not available in database')

        if s.closed is True:
            raise IOError('read on closed Data object')

        # total available bytes from current position
        available = s.length - s._pos

        if size > available or size == -1:
            toread = available
        elif size == 0:
            return bytes()
        elif size < -1:
            raise ValueError("read length must be positive or -1")
        else:
            toread = size

        if available == 0:
            # from https://docs.python.org/3.4/library/io.html:
            # "If the object is in non-blocking mode and no bytes are
            # available, None is returned." But, we've seen that this goes
            # wrong in lxml.etree, when trying to read the last block. So
            # instead we return empty bytes object
            return bytes()

        result = bytearray(toread)
        s.readinto(result, debug)
        result = bytes(result)
        return result


    def readable(s):
        ''' check if data object is readable '''

        # data may not be available
        if s.stored is False:
            return False

        # if it is open, it is readable
        return not s.closed


    def _init_cache(s, readpos, debug=False):
        ''' builts a cache starting at given readpos '''

        if readpos > s.length:
            raise ValueError('cannot read cache beyond data')

        if readpos < 0:
            raise ValueError('readpos cannot be negative')

        # the max position at which it is sane to start a cache
        max_readpos = s.length - CACHESIZE

        if readpos > max_readpos:
            # make sure we fully utilize our cache block
            s._cache_start = max_readpos
            # prevent negative cache start:
            if s._cache_start < 0:
                s._cache_start = 0
            s._cache_end = max_readpos + CACHESIZE
        else:
            s._cache_start = readpos
            s._cache_end = s._cache_start + CACHESIZE

        if s._cache_end > s.length:
            # this should not happen, because we set max_readpos above
            raise ValueError("bug in _init_cache")

        cache_size = s._cache_end-s._cache_start

        if debug is True:
            print("MIS: cachestart: {:d}, cacheend: {:d}, "
                  "cachesize: {:d}".format(s._cache_start,
                    s._cache_end, cache_size))

        s._cache = bytearray(cache_size)
        s._readcache(s._cache, s._cache_start, debug)


    def _readcache(s, b, readpos, debug=False):
        ''' read buffer b by reading at readpos '''

        # number of byte to read in total
        toread = len(b)
        # current position in the output array
        outpos = 0

        if toread > (s.length - readpos):
            raise IOError('more bytes requested than available')

        # perform the block query
        s._cursor.execute(s._data_manager.block_query, (s._dataid, readpos, readpos+toread))

        for boffset, blkid, bsize, bdata in s._cursor:

            # amount of bytes available in this block,
            # taking read position into account
            available = boffset + bsize - readpos

            if debug:
                print("DB: blkid: {:d}, boffset: {:d}, bsize: {:d}, "
                      " readpos: {:d}, available: {:d},"
                      " toread: {:d}".format(blkid, boffset,
                          bsize, readpos, available, toread))

            if available >= toread:
                # all remaining bytes are in this block
                blockread = toread
                toread -= blockread

            else:
                # the block does not contain all remaining bytes
                blockread = available
                toread -= blockread

            # the start and end position to read from the current block
            breadpos = readpos-boffset
            breadend = breadpos + blockread

            # copy bytes from blockdata into buffer b
            b[outpos:outpos+blockread] = bdata[breadpos:breadend]

            # update offsets and amount of read bytes
            readpos += blockread
            outpos += blockread

        # if we get here, these checks should pass
        if toread != 0:
            raise ValueError('toread should be 0 here!')
        if outpos != len(b):
            raise ValueError('outpos should be exactly buffer size!')

        return outpos


    def readinto(s, b, debug=False):
        ''' read bytes into given byte array '''

        if s.stored is False:
            raise IOError('data is not available in database')

        if s.closed is True:
            raise IOError('read on closed Data object')

        # number of bytes to read in total
        toread = len(b)
        # current read position
        readpos = s._pos
        # current position in the output array
        outpos = 0

        if toread > (s.length - s._pos):
            raise IOError('not enough bytes available to fill provided array')

        # make sure initial readpos is inside cache
        if s._cache_start > readpos or readpos >= s._cache_end:
            s._init_cache(readpos, debug)

        # amount of bytes available in cache
        available = s._cache_end - readpos
        # current position in the cache
        cpos = readpos - s._cache_start

        while available < toread:
            if debug is True:
                print('HIT: toread: {:}, readpos: {:}, '
                      'outpos: {:}, available: {:}, '
                      'cpos: {:}'.format(toread, readpos, outpos, available,
                          cpos))
            # not all data is available in cache, read up to end of cache
            b[outpos:outpos+available] = s._cache[cpos:cpos+available]
            outpos += available
            readpos += available
            toread -= available
            s._init_cache(readpos, debug)
            cpos = readpos - s._cache_start
            available = s._cache_end - readpos


        # if we get here, we should be in final cache block
        if available >= toread:
            if debug is True:
                print('HIT: toread: {:}, readpos: {:}, '
                      'outpos: {:}, available: {:}, '
                      'cpos: {:}'.format(toread, readpos, outpos, available,
                          cpos))

            # entire block is in cache
            b[outpos:outpos+toread] = s._cache[cpos:cpos+toread]
            readpos += toread
            # update position
            s._pos = readpos
            # outpos equals amount of bytes read
            return outpos

        raise IOError('We should not get here!')


    def readline(s, size=-1):
        ''' Read and return a line from the data object '''

        # local readbuffer
        bufsize = 256
        # keep track of starting position
        startpos = s._pos
        # the total amount of bytes copied in the bytesIO object
        bytes_copied = 0
        # the result bytesIO object
        result = _BytesIO()

        # check how many bytes area available from current position
        available = s.length - s._pos

        if size == -1:
            remaining = available
        elif size > 0 and size > available:
            remaining = available
        elif size > 0:
            remaining = size
        else:
            raise ValueError("invalid size argument")

        # keep reading buffers until newline is found
        while True:
            if remaining < bufsize:
                buf = s.read(remaining)
                remaining = 0
            else:
                buf = s.read(bufsize)
                remaining -= bufsize

            newline_at = buf.find(b'\n')
            if newline_at == -1:
                # copy entire buffer into result bytesIO object
                bytes_copied+=result.write(buf)
            else:
                # copy all up to and including the newline into result buffer
                endpos = newline_at+1
                bytes_copied += result.write(buf[0:endpos])
                # update the fileposition to next byte after newline
                s._pos = startpos + bytes_copied
                result.seek(0)
                return result.read()

            if remaining == 0:
                # update fileposition and return buffer
                s._pos = startpos + bytes_copied
                result.seek(0)
                return result.read()


    def readlines(s):
        ''' Return lines from the data object
        '''
        return (l for l in s)


    def seek(s, offset, whence=0):
        ''' seek to offset from start, curpos or end of data '''

        if s.seekable() is False:
            raise IOError("Cannot seek in non-seekable file. Is data stored?")

        # NOTE: we do not update positions of underlying apsw.blob objects,
        # this is all handled inside readinto

        if whence == 0:
            newpos = offset
        elif whence == 1:
            newpos = s._pos + offset
        elif whence == 2:
            newpos = s.length + offset

        if newpos > s.length or newpos < 0:
            raise ValueError('The resulting offset would be less than '
                                 'zero or past the end of the blob')
        s._pos = newpos


    def seekable(s):
        ''' check if data is seekable '''
        if s.stored is False:
            return False

        return not s.closed


    def tell(s):
        ''' return current position '''
        return s._pos


    def truncate(s):
        ''' unsupported '''
        raise _UnsupportedOperation("truncate")


    def writable(s):
        ''' return False '''
        return False


    def writelines(s, lines):
        ''' unsupported '''
        raise _UnsupportedOperation("writelines")


    def write(s, b):
        ''' unsupported '''
        raise _UnsupportedOperation("write")


    def __del__(s):
        ''' deconstructor '''
        s.close()
        super().__del__()


    def _check_length(s):
        ''' check the length property by performing a query '''

        if s.stored is False:
            raise IOError("cannot check length of non-stored data")

        if s.stored is True:
            s._cursor.execute(s._data_manager.size_query, (s._dataid,))
            length = s._cursor.fetchone()[0]
        else:
            length = 0

        if length != s.length:
            raise IOError('length of combined blocks does not match stored length')
