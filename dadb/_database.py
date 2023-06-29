''' database.py - Database object for DADB.

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

# global imports
import os as _os
from collections import namedtuple as _nt
from collections import OrderedDict as _OD
from enum import EnumMeta as _EnumMeta
from enum import Enum as _Enum
from datetime import datetime as _datetime
import apsw as _apsw
from copy import deepcopy as _deepcopy

# package imports
from ._schema import _reserved_
from ._schema import _operational_tables_
from ._schema import _data_tables_
from ._schema import ENUMTBLNAME, MODELTBLNAME, FIELDTBLNAME
from ._schema import MAPTBLNAME, PROPTBLNAME, SCHEMAVERSION
from ._schema import enum_tabledef as _enum_tabledef
from ._schema import create_timeline_view as _create_timeline_view
from ._schema import create_fieldinfo_view as _create_fieldinfo_view
from ._schema import validname as _validname

from ._model_definition import field_definition as _field_definition
from ._model_definition import model_definition as _model_definition
from ._model_definition import convert_fielddefinitions as _convert_fielddefinitions

from ._datatype import typedesc as _typedesc
from ._datatype import basictypes as _basictypes
from ._datatype import isoformat as _isoformat
from ._datatype import equivalent_datatype as _equivalent_datatype

from ._common import APIVERSION
from ._common import DBPREFIX, TABLEPREFIX, FIELDPREFIX

from ._data import Data as _Data
from ._data import DataInserter as _DataInserter
from ._data import DataManager as _DataManager

from ._model import Model as _Model

from . import _exceptions


class Database:
    ''' The main database class for DADB databases '''


    #########################
    # Generic DB operations #
    #########################


    def __init__(s, dbname, prefix=DBPREFIX, pkey='id'):
        ''' initialise the database object. '''

        # properties related to the database file and connection
        s.dbname = _os.path.abspath(_os.path.expanduser(dbname))
        s.connected = False
        s.hascursor = False
        s.loaded = False
        s.created = False

        # prefix that is to be used in all static table and column names
        s.prefix = prefix
        # default name of the integer primary key column
        s.pkey = pkey

        # dictionary for holding the registered models: {name:Model}
        s.models = {}
        # dictionary for holding the rowids of each model in the _model_ table
        s.modelrows = {}
        # dictionary for holding the registered enums: {name:enumdescriptor}
        s.enums = {}
        # dictionary of table descriptors {name:tabledescriptor}
        s.tables = {}

        # register the basic datatypes {name:typedescriptor}
        s.datatypes = _deepcopy(_basictypes)

        # add the Data datatype
        s._register_Data_dtype()

        # we also need a reverse lookup dictionary by datatype
        s._rev_datatypes = {dtype.class_:dtype for dtype in s.datatypes.values()}

        # prepare the DataInserter and DataManager
        s.data_inserter = _DataInserter(s.prefix)
        s.data_manager = _DataManager(s.prefix)

        # keep track of models for which modelitems may be written
        # (writing is only allowed if register_model has been called
        #  at least once in the active process, in order to make sure
        #  that the writer has the proper version of the model)
        s._writing_allowed = set()


    def __del__(s):
        ''' deconstructor '''
        # release the APSW connection
        s.close()


    def connect(s):
        ''' opens a connection to the database file '''

        if s.connected is True and s.hascursor is True:
            return
        elif s.connected is True:
            s.dbcur = s.dbcon.cursor()
            s.hascursor = True
        else:
            s.dbcon = _apsw.Connection(s.dbname)
            s.dbcur = s.dbcon.cursor()
            s.connected = True
            s.hascursor = True


    def close(s):
        ''' closes the connection to the database file. '''

        if s.hascursor:
            s.dbcur.close()

        if s.connected:
            s.dbcon.close()

        s.connected = False
        s.hascursor = False
        s.dbcon = None
        s.dbcur = None


    def begin_transaction(s):
        ''' begins transaction on main database connection, returns True upon
        success, or False when we are already inside a transaction '''

        # NOTE: if some exception is raised during a transaction, the entire
        # transaction will be rolled-back, no need for additional handling
        # of individual exceptions (source: apsw docs + experiment)

        try:
            s.dbcur.execute('BEGIN TRANSACTION')
            return True
        except _apsw.SQLError as e:
            if e.args[0] == 'SQLError: cannot start a transaction within a transaction':
                return False
            else:
                raise


    def end_transaction(s):
        ''' issue a commit on the current db connection '''

        # a function with a single statement should be avoided, but
        # this is for API purposes
        s.dbcur.execute('COMMIT')


    def rollback_transaction(s):
        ''' issue rollback on main database connection '''

        try:
            s.dbcur.execute('ROLLBACK')
            return True
        except _apsw.SQLError as e:
            if e.args[0] == 'SQLError: cannot rollback - no transaction is active':
                return False
            else:
                raise


    def vacuum(s):
        ''' try to reduce database size by issuing a VACUUM command '''
        try:
            s.dbcur.execute('VACUUM')
        except _apsw.SQLError as e:
            if e.args[0] == 'SQLError: cannot VACUUM - SQL statements in progress':
                # disconnect and reconnect should solve this
                s.close()
                s.connect()
                s.dbcur.execute('VACUUM')
            else:
                raise


    def create(s):
        ''' creates a new database with appropriate tables and structures. '''

        if s.loaded is True:
            raise RuntimeError('you can either load or create a db')
        if s.created is True:
            raise RuntimeError('db already created. did you forget?')

        directory = _os.path.split(s.dbname)[0]
        if not _os.path.isdir(directory):
            _os.mkdir(directory)

        if _os.path.exists(s.dbname):
            msg = 'I refuse to overwrite the existing file {:s}.'
            raise RuntimeError(msg.format(s.dbname))

        # connect to the database
        s.connect()

        # set pagesize prior to WAL mode (https://www.sqlite.org/pragma.html)
        # set to 16K based on asumption that we have many data objects <= 100k
        # and the following page:
        # https://www.sqlite.org/intern-v-extern-blob.html
        s.dbcur.execute('PRAGMA page_size=16384')
        # journal mode to WAL (performance gain over journal mode)
        s.dbcur.execute('PRAGMA journal_mode=WAL;')

        # make sure it all happens or nothing at all
        s.dbcur.execute('BEGIN TRANSACTION')

        # create the reserved table
        s._register_table(_reserved_, create=True)
        resrec = s.tables[_reserved_.name].record
        resrec = resrec(s.pkey, SCHEMAVERSION, APIVERSION, s.prefix)
        rowid = s._insert_record(_reserved_.name, resrec, cursor=s.dbcur)

        # register and create the operational and data tables
        tbldefs = [t for t in _operational_tables_]
        tbldefs.extend([s._add_prefix(t, s.prefix) for t in _data_tables_])
        for t in tbldefs:
            s._register_table(t, create=True)

        # create static views
        _create_fieldinfo_view(s)
        _create_timeline_view(s)

        # end transaction again
        s.dbcur.execute('COMMIT')

        s.created = True


    def load(s, custom_tables=None):
        ''' initializes the database object values by reading from database '''

        # NOTE: no transaction needed, only selects
        # NOTE: re-creation of views not needed here, they exist

        if s.connected is False or s.hascursor is False:
            s.connect()

        if s.created is True:
            raise RuntimeError('you can either load or create a db')
        if s.loaded is True:
            raise RuntimeError('db already loaded')

        # load the reserved table
        s._register_table(_reserved_, create=False)
        res = list(s.select(_reserved_.name, cursor=s.dbcur))
        if len(res) != 1:
            raise ValueError('expected a single record in _reserved_ table')
        res = res[0]
        s.prefix = getattr(res, 'prefix_')
        s.pkey = getattr(res, 'pkey_')
        sv = getattr(res, 'schemaversion')
        if isinstance(sv, str):
            msg = 'db schema {:s} != DADB schema {:d}'.format(sv, SCHEMAVERSION)
            raise _exceptions.VersionError(msg)
        if sv != SCHEMAVERSION:
            msg = 'db schema {:d} != DADB schema {:d}'.format(sv, SCHEMAVERSION)
            raise _exceptions.VersionError(msg)

        api = getattr(res, 'apiversion')
        if api != APIVERSION:
            msg = 'db API version {:d} != DADB API version {:d}'.format(api, APIVERSION)
            raise _exceptions.VersionError(msg)

        # load the in memory representation of the operational and data tables
        tbldefs = [t for t in _operational_tables_]
        tbldefs.extend([s._add_prefix(t, s.prefix) for t in _data_tables_])

        # make sure these tables exist and register them
        for t in tbldefs:
            # test if the table exists, abort otherwise
            r = list(s.select('sqlite_master', fields=['name'],
                              where={'type':'table','name':t.name},
                              cursor=s.dbcur))
            if len(r) != 1:
                raise ValueError('trying to load corrupt or uninitialized database')
            s._register_table(t, create=False)

        # load the enums and the models
        s._load_enums()
        s._load_models()

        s.loaded = True


    def reload(s):
        ''' updates database object values by reloading database '''

        if s.loaded is False and s.created is False:
            raise RuntimeError('cannot reload an unitialized db')

        s.loaded = False
        s.created = False

        # make sure we only remove tables that are managed by us,
        # since user may have defined their own tables to the database
        # that are not managed by DADB
        remove_tables = set([])

        # the _reserved_ table
        remove_tables.add(_reserved_.name)

        # the other tables defined here
        tbldefs = [t for t in _operational_tables_]
        tbldefs.extend([s._add_prefix(t, s.prefix) for t in _data_tables_])

        for t in tbldefs:
            remove_tables.add(t.name)

        # the model related tables
        for m in s.models.values():
            remove_tables.add(m.tabledef.name)
            for fd in m.fielddescriptors.values():
                if fd.proptable != None:
                    remove_tables.add(fd.proptable.tabledef.name)
                if fd.maptables != []:
                    remove_tables.update([m.tabledef.name for m in fd.maptables])

        # the enum related tables
        for e in s.enums.values():
            remove_tables.add(e.tabledef.name)

        # and remove them
        for t in remove_tables:
            v = s.tables.pop(t)

        # clear out the models and enums structures
        s.models = {}
        s.enums = {}

        # load the database again
        s.load()


    def _add_prefix(s, tabledef, prefix):
        ''' adds a prefix to the given tabledefintion by adding it to
        the tablename and to the names of each of the columns. '''

        fields = tuple([c._replace(name=prefix+c.name) for c in tabledef.fields])
        # replace the fieldnames in tblconstraint with prefixed versions
        # (NOTE: this is somewhat dangerous string-parsing)
        tcons = tabledef.tblconstraint
        if tcons != None:
            tokens = [t.lstrip('(').rstrip(',').rstrip(')') for t in tcons.split()]
            fldnames = [f.name for f in tabledef.fields]
            for t in tokens:
                if t in fldnames:
                    tcons = tcons.replace(t, s.prefix+t, 1)
        return tabledef._replace(name=prefix+tabledef.name, fields=fields,
                                 tblconstraint=tcons)


    ####################
    # Table operations #
    ####################


    def _register_table(s, tabledef, create=True):
        ''' registers and creates a new table in the database '''

        if tabledef.name in s.tables:
            if tabledef == s.tables[tabledef.name].tabledef:
                # this table is already registered
                return tabledef.name
            else:
                raise ValueError("a different table with that name already exists")

        # create the table
        if create is True:
            # No need for starting transaction, dedicated cursor used
            s._create_table(tabledef)
        else:
            # table should exist
            # NOTE: tested: PRAGMA statement does not break transaction, so
            # safe to use main dbcur when caller initiated transaction
            q = 'PRAGMA table_info({:})'.format(tabledef.name)
            s.dbcur.execute(q)
            if s.dbcur.fetchone() == None:
                raise ValueError("table should already exist when create=False")

        # create a namedtuple for the individual records
        record = _nt(tabledef.name, [f.name for f in tabledef.fields])
        # create and store the table descriptor

        # store table definitions in a tabledescriptor dict
        _tbldesc = _nt('tabledescriptor', 'tabledef record')
        s.tables[tabledef.name] = _tbldesc(tabledef, record)

        return tabledef.name


    def _create_table(s, tabledef):
        ''' builds and executes a CREATE TABLE statement for given table. '''

        head = 'CREATE TABLE IF NOT EXISTS {:s} ('.format(tabledef.name)
        if tabledef.tblconstraint is not None:
            foot = ', {:s});'.format(tabledef.tblconstraint)
        else:
            foot = ');'.format(tabledef.tblconstraint)
        cols = ['{:s} {:s}'.format(c.name, c.coldef) for c in tabledef.fields]
        stmnt = head +", ".join(cols) + foot

        # CREATE TABLE statement splits up transactions, use dedicated cursor
        s.dbcon.cursor().execute(stmnt)


    def _drop_table(s, tablename):
        ''' drops the table with the given tablename '''

        if tablename not in s.tables:
            raise ValueError("no such table")

        q = 'DROP TABLE IF EXISTS {:s}'.format(tablename)
        # assumption: DROP TABLE breaks transactions, so use separate cursor
        s.dbcon.cursor().execute(q)
        discard = s.tables.pop(tablename)


    def _insert_values(s, tablename, *values, cursor=None, debug=False):
        ''' inserts given values into given table.

        This is only usable for insertion of record with all columns known
        (not for integer primary key autoincrementing records), use
        _insert_record for that case.

        If cursor if given, this is used, which allows caller to manage
        transactions. Otherwise a dedicated cursor is created.

        NOTE: The returned rowid is only valid when only a single thread
        is used for insert, so make sure that we do not have concurrent
        writers!
        '''

        if cursor is None:
            # use a dedicated cursor
            cursor = s.dbcon.cursor()

        qmarks = ",".join(["?"]*len(values))
        statement = "INSERT INTO {:s} VALUES ({:s});".format(tablename, qmarks)

        if debug is True:
            print(statement)

        cursor.execute(statement, values)

        # get the rowid via last_insert_rowid.
        # NOTE: This is only safe when a single thread is performing inserts!
        # when we need concurrent inserts (which is probably not needed)
        # we might consider using sqlite_sequence table for this?
        rowid = s.dbcon.last_insert_rowid()
        return rowid


    def _insert_record(s, tablename, record, cursor=None, debug=False):
        ''' inserts the given record into given table.

        All fields that have value None will be set to NULL in database.

        If cursor if given, this is used, which allows caller to manage
        transactions. Otherwise a dedicated cursor is created.

        NOTE: The returned rowid is only valid when only a single thread
        is used for insert, so make sure that we do not have concurrent
        writers!
        '''

        if cursor is None:
            # use a dedicated cursor
            cursor = s.dbcon.cursor()

        # select only those columns that are not None
        names = [f for f in record._fields if getattr(record, f) is not None]
        values = [v for v in record if v is not None]

        # build and execute the INSERT statement
        qmarks = ",".join(["?"]*len(values))
        names = ",".join(names)
        statement = "INSERT INTO {:s}({:s}) VALUES({:s}); "
        statement = statement.format(tablename, names, qmarks)

        if debug is True:
            print(statement)

        cursor.execute(statement, values)
        rowid = s.dbcon.last_insert_rowid()
        return rowid


    def select(s, tablename, fields=None, where=None, orderby=None, debug=False, cursor=None):
        ''' wrapper for simple SELECT statement, yielding result as namedtuples

        Only support queries on single tables with an optional list of fields
        to select (default: None; this means all fields are selected) and an
        optional dictionary from which the WHERE clause is built
        (default: None; this means no WHERE clause is built at all)

        If you bring your own cursor, that will be used, otherwise we create a
        dedicated cursor for just this select, which may introduce some unknown
        overhead. This behavior is changed from using the main database cursor
        by default to prevent any problems with nested queries. If you want to
        use the main cursor, just provide it as kwarg (cursor=db.dbcur).

        According to apsw docs, creating cursors is 'cheap', so should be ok.

        Warning: this is a generator and results are produced by iterating over
        the cursor. If you brought your own cursor and perform nested queries,
        make sure to expand results to a list first (or leave out the cursor
        argument, which solves the problem for you by using a dedicated
        cursor).

        NOTE: this function creates a new named tuple for each call, so when
        calling this often, the overhead of creating similar namedtuple
        classess will become a performance hog. Best to create a dedicated
        query in that case
        '''

        if cursor is None:
            cursor = s.dbcon.cursor()

        # if fields is not given, we need to get the fields ourselves
        if fields is None or fields == ['*']:
            cursor.execute('PRAGMA table_info(%s)' % (tablename))
            fields = [r[1] for r in cursor]

        if fields == []:
            # the table doesn't exist or has no columns, nothing to yield
            return

        fields = ', '.join(fields)
        result = _nt('results',fields)

        if where is not None:
            # make sure we have fields and values in same order
            wnames = [k for k in where.keys()]
            wvals = tuple([where[n] for n in wnames])
            # build the WHERE clause
            where = 'WHERE ' + ' AND '.join(['%s is ?' % n for n in wnames])
            if orderby is not None:
                where += ' ORDER BY {:s}'.format(orderby)
            query = 'SELECT {:s} FROM {:s} {:s};'.format(fields, tablename, where)
            if debug is True:
                print(query, wvals)
            cursor.execute(query, wvals)

        else:
            query = 'SELECT {:s} FROM {:s};'.format(fields, tablename)
            if orderby is not None:
                query += ' ORDER BY {:s}'.format(orderby)
            if debug is True:
                print(query)
            cursor.execute(query)

        for res in cursor:
            yield result(*res)


    ##############################
    # Data related functionality #
    ##############################


    def _register_Data_dtype(s):
        ''' register the 'Data' datatype to the database '''

        data_dtype = _typedesc('Data', _Data, 'INTEGER',
                               lambda value: s.insert_data(value),
                               lambda value: s.get_data(value))
        s.datatypes['Data'] = data_dtype


    def insert_data(s, fileobj, offset=0, length=None):
        ''' stores the data in the given fileobject into the database. returns
        the rowid of the corresponding data record. If offset and/or length are
        given, a slice of the given fileobject data is inserted. The hashes
        md5, sha1 and sha256 are calculated on the fly.

        Note: if the fileobj is not seekable, the caller must make sure the
        current position is correct. Otherwise, we seek to offset 0 before
        insert.
        '''

        return s.data_inserter.insert_data(s.dbcon, fileobj, offset, length)


    def insert_unstored_data(s, fileobj, offset=0, length=None):
        ''' Adds an entry in the data table, without actually storing any data
        blocks.  This can be useful for storing metadata about large binary
        objects for which it is not required to store the actual data '''

        return s.data_inserter.insert_unstored_data(s.dbcon, fileobj, offset, length)


    def get_data(s, id_):
        ''' returns the data in the data table with the given id as Data object '''

        if id_ is None:
            return None
        return s.data_manager.get_data(s.dbcon, id_)


    def data_by_sha256(s, sha256):
        ''' returns rowids of data objects with the given sha256 '''

        # use dedicated cursor
        c = s.dbcon.cursor()
        return s.data_manager.data_by_sha256(sha256, c)


    def remove_duplicate_blocks(s):
        ''' removes duplicate blocks and vacuum database '''

        # make sure we are in a single transaction
        started_transaction = s.begin_transaction()
        if started_transaction is False:
            raise RuntimeError("remove_duplicate_blocks can not be part " +\
                               "of some other transaction")

        # create an index on the blockmap table to speed this up
        s.dbcur.execute(s.data_manager.make_blockmap_idx_query)
        # finish the transaction
        s.end_transaction()

        # get the duplicate blocks (put in a list to prevent
        # having an active select during updates of the same tables
        duplicates = list(s.data_manager.duplicate_blocks(s.dbcon.cursor()))

        # actually remove the blocks within a single transaction
        s.begin_transaction()
        s.data_manager.remove_duplicate_blocks(duplicates, s.dbcur)
        s.end_transaction()

        # remove the index again
        try:
            s.begin_transaction()
            s.dbcur.execute(s.data_manager.drop_blockmap_idx_query)
        except _apsw.LockedError:
            # NOTE: we sometimes got a database table is locked error, when
            # removing the index again. This can happen if we try to DROP the
            # index when some SELECT statement is still in PENDING state according to:
            # https://www.arysontechnologies.com/blog/fix-sqlite-error-database-locked/.
            # I'm not sure under which circumstances this occurs exactly, but
            # a workaround seems to be to disconnect and connect to the
            # database again.
            print("[!] database table locked, reconnect to database")
            s.close()
            s.connect()
            s.begin_transaction()
            s.dbcur.execute(s.data_manager.drop_blockmap_idx_query)
        finally:
            s.end_transaction()

        # reduce the size of the database file
        s.vacuum()


    ##############################
    # Enum related functionality #
    ##############################


    def register_enum(s, enum, source, version, tableprefix=TABLEPREFIX):
        ''' registers a single enum and return the table name '''

        # get the name directly from the enum
        name = enum.__name__

        # check if we have an exact duplicate of this enum already
        if s._has_enum(enum, tableprefix, source, version):
            return s.enums[name].tabledef.name

        # if we get here and we have an enum or a model with the
        # given name, reject the registration
        if name in s.enums:
            raise ValueError("A different Enum is already registered with that name")
        if name in s.models:
            raise ValueError("An enum cannot have the same name as a Model")

        # make sure we are in a transaction
        started_transaction = s.begin_transaction()

        # create the table that holds the enum
        tblname = _validname(name, tableprefix)
        tblname = _validname(tblname, s.prefix)
        tabledef = _enum_tabledef(s.prefix, tblname)
        tablename = s._register_table(tabledef, create=True)

        # insert entry in enum metadata table
        rec = s.tables[ENUMTBLNAME].record
        enumrec = rec(None, name, tblname, source, version, tableprefix)
        rowid = s._insert_record(ENUMTBLNAME, enumrec, cursor=s.dbcur)

        # insert the enum members
        for val in enum.__members__.values():
            rid = s._insert_values(tblname, int(val.value), val.name,
                                   cursor=s.dbcur)

        # we already have the appropriate information to create a table
        # descriptor, but instead we want to create a new underlying enum that
        # is created in this module and not in the import module. So instead we
        # create the enumdescriptor, including the new enum, by reading from
        # the newly created records (rationale: we want our own internal enums,
        # in order to make enums from various import modules comparable)
        enumdesc = s._load_enum(name)
        s.enums[name] = enumdesc

        # sanity check
        if enumdesc.tabledef != tabledef:
            if started_transaction is True:
                s.rollback_transaction()
            raise RuntimeError('error in enum registration: tabledef')
        if enumdesc.rowid != rowid:
            if started_transaction is True:
                s.rollback_transaction()
            raise RuntimeError('error in enum registration: rowid')
        if enumdesc.source != source:
            if started_transaction is True:
                s.rollback_transaction()
            raise RuntimeError('error in enum registration: source')
        if enumdesc.version != version:
            if started_transaction is True:
                s.rollback_transaction()
            raise RuntimeError('error in enum registration: version')
        if enumdesc.table_prefix != tableprefix:
            if started_transaction is True:
                s.rollback_transaction()
            raise RuntimeError('error in enum registration: table_prefix')

        if started_transaction is True:
            s.end_transaction()

        return tblname


    def drop_enum(s, enumname):
        ''' removes the enum with the given name from the database '''

        if not enumname in s.enums:
            raise ValueError("No such enum")

        rowid = s.enums[enumname].rowid
        tablename = s.enums[enumname].tabledef.name

        # make sure we are inside a transaction
        started_transaction = s.begin_transaction()

        # first, check if this model is a dependency of a model
        q = '''SELECT modelname_
                FROM _fieldinfo_
                JOIN '''+MODELTBLNAME+'''
                ON _fieldinfo_.modeltable_ == '''+MODELTBLNAME+'''.table_
                WHERE _fieldinfo_.maps_to_ == ?
                OR _fieldinfo_.points_to_ == ?
                '''

        s.dbcur.execute(q, (tablename, tablename))
        res = s.dbcur.fetchone()
        if res is not None:
            modelname = str(res[0])
            raise ValueError("I refuse: Enum is dependency of model: {:s}".format(modelname))

        # remove the enum
        q = 'DELETE FROM '+ENUMTBLNAME+' WHERE id_ == ?'
        s.dbcur.execute(q, (rowid,))

        # remove the enum from the enum dict
        discard = s.enums.pop(enumname)

        # remove the enum table (dedicated cursor)
        s._drop_table(tablename)

        # end transaction
        if started_transaction is True:
            s.dbcur.execute('COMMIT')


    def _load_enum(s, name):
        ''' reads an enum from the enum table and creates an enumdescriptor '''

        # read the enum metadata from the enum table
        r = list(s.select(ENUMTBLNAME, where={'name_':name}, cursor=s.dbcur))
        if len(r) == 0:
            raise ValueError("no such enum: {:s}".format(name))
            return None
        elif len(r) > 1:
            raise RuntimeError("corrupt db: multiple enums with the same name")
        else:
            r = r[0]

        tblname = getattr(r, 'table_')
        rowid = getattr(r, 'id_')
        source = getattr(r, 'source_')
        version = getattr(r, 'version_')
        tblprefix = getattr(r, 'table_prefix_')

        # read the value, name pairs from the enum's table and create enum
        valnames = list(s.select(tblname, debug=False, cursor=s.dbcur))
        values = {v:k for k,v in valnames}
        # create the Enum class
        enum = _Enum(name, values)

        # create the table definition to complete the enum descriptor
        tabledef = _enum_tabledef(s.prefix, tblname)

        # return the enumdescriptor
        _enumdesc = _nt('enumdescriptor', 'name enum tabledef '
                                          'source version rowid '
                                          'table_prefix')

        return _enumdesc(name, enum, tabledef, source, version, rowid, tblprefix)


    def _load_enums(s):
        ''' loads all enums from the database into s.enums '''

        # expand to list, for nested queries
        rs = list(s.select(ENUMTBLNAME, fields=['name_'], cursor=s.dbcur))
        for r in rs:
            name = getattr(r, 'name_')
            if name in s.enums:
                raise ValueError("An Enum with that name is already registered")
            enumdesc = s._load_enum(name)
            s.enums[name] = enumdesc
            s._register_table(enumdesc.tabledef, create=False)


    def _has_enum(s, enum, table_prefix, source, version):
        ''' return True if the given enum is already registered '''

        # get the name directly from the Python Enum
        name = enum.__name__

        if name in s.enums:
            if s.enums[name].table_prefix != table_prefix:
                return False
            if s.enums[name].source != source:
                return False
            if s.enums[name].version != version:
                return False
            if not _equivalent_datatype(enum, s.enums[name].enum):
                return False

            return True
        return False


    #############
    # Model API #
    #############


    def register_model(s, modeldef, tableprefix=TABLEPREFIX, fieldprefix=FIELDPREFIX):
        ''' Adds the required tables and records for the given model '''

        # using a fieldprefix is mandatory to prevent name clashes when a model
        # has a field that matches the primary key field name (default: 'id'.
        # The default primary key column uses the name 'id', which results in
        # the column '[prefix]id' (often 'xid'). User-defined or detected
        # models with a field called 'id' will be named
        # '[prefix][fieldprefix]id', when a fieldprefix is used, which prevents
        # such name clashes.
        if fieldprefix=='':
            raise ValueError('using a non-blank fieldprefix is mandatory')

        # This function requires that models that depend on other models (i.e.
        # one of the fields is another model) are registered after the model on
        # which it depends. The same holds for enums. The rationale for this is
        # that defining models is the task of the calling module and that the
        # complexities of resolving such dependencies should be left there.

        # A model that is defined by a user may contain fields with submodels.
        # In this case, the submodels are "modeldefinitions". This function
        # converts these definitions into field definitions that contain the
        # actual Model class for the submodel
        new_fielddefs = _convert_fielddefinitions(modeldef.fielddefs)
        modeldef = modeldef._replace(fielddefs=new_fielddefs)

        # get the submodels and subenums this model relies on
        # (will raise an error when unsatisfied dependencies exist)
        submodels, subenums = s._get_dependencies(modeldef.fielddefs)

        # create a Model object
        model = _Model(modeldef, s.pkey, s.prefix, tableprefix, fieldprefix,
                       s.datatypes, submodels=submodels, subenums=subenums)

        # if this model is already registered, use that one instead
        if s._has_model(model):
            s._writing_allowed.add(model.name)
            return s.models[model.name]

        # but if another model exists that is not equivalent, this is an error
        if model.name in s.models:
            msg = "A model with that name is already registered: {:s}".format(model.name)
            raise _exceptions.InconsistencyError(msg)
        if model.name in s.enums:
            msg = "An enum with that name is already registered: {:s}".format(model.name)
            raise _exceptions.InconsistencyError(msg)

        # start transaction on main cursor if not yet inside one
        started_transaction = s.begin_transaction()

        # create the tables for this model
        s._create_model_tables(model)

        # insert entry in model table
        rec = s.tables[MODELTBLNAME].record
        modelrec = rec(None, model.name, model.tabledef.name, model.source,
                       model.version,
                       model.tableprefix, model.fieldprefix,
                       model.explicit_dedup, model.implicit_dedup,
                       model.fail_on_dup)
        rowid = s._insert_record(MODELTBLNAME, modelrec, cursor=s.dbcur)

        # add the model to the model dictionary
        s.models[model.name]=model
        # and store the rowid of this model
        s.modelrows[model.name]=rowid

        # add the field, maptable and proptable records
        s._insert_model_metadata(model, rowid)

        # update the timeline view with the new model
        _create_timeline_view(s)

        # end transaction if we started it
        if started_transaction is True:
            s.end_transaction()

        # set writing allowed for this model in the loaded db object
        s._writing_allowed.add(model.name)

        return model


    def _get_dependencies(s, fielddefinitions):
        ''' return submodel and subenum dict from fielddefinitions, raising an
        error when the dependency is not satisfied '''

        # identify submodels and subenums
        submodels = []
        subenums = []
        for fd in fielddefinitions:
            if isinstance(fd.types, tuple):
                for t in fd.types:
                    if hasattr(t, '_fields'):
                        submodels.append(t)
                    elif isinstance(t, _EnumMeta):
                        subenums.append(t)
                    elif not s._known_datatype(t):
                        msg = 'Unkown datatype in fielddefinition: {:s}'.format(t)
                        raise _exceptions.UnsatisfiedDependencyError(msg)
            elif hasattr(fd.types, '_fields'):
                submodels.append(fd.types)
            elif isinstance(fd.types, _EnumMeta):
                subenums.append(fd.types)
            elif not s._known_datatype(fd.types):
                msg = 'Unkown datatype in fielddefinition: {:s}'.format(t)
                raise _exceptions.UnsatisfiedDependencyError(msg)

        # NOTE that the fielddefinitions may contain models or enums that where
        # generated in another module with all fields and the name equal, but
        # the internal id or internal name different. # Hence, we use the
        # equivalent_datatype function to determine if the same model/enum is
        # intended.

        mdict = {}
        for sm in submodels:
            if sm.__name__ in s.models:
                if _equivalent_datatype(sm, s.models[sm.__name__].modelclass):
                    mdict[sm.__name__] = s.models[sm.__name__]
                else:
                    msg = 'Non-equivalent model exists with the same name {:s}'.format(sm.__name__)
                    raise _exceptions.InconsistencyError(msg)
            else:
                msg = 'Required model {:s} not yet registered'.format(sm.__name__)
                raise _exceptions.UnsatisfiedDependencyError(msg)

        edict = {}
        for se in subenums:
            if se.__name__ in s.enums:
                if _equivalent_datatype(se, s.enums[se.__name__].enum):
                    edict[se.__name__] = s.enums[se.__name__]
                else:
                    msg = 'Non-equivalent enum exists with the same name {:s}'.format(se.__name__)
                    raise _exceptions.InconsistencyError(msg)
            else:
                msg = 'Required enum {:s} not yet registered'.format(se.__name__)
                raise _exceptions.UnsatisfiedDependencyError(msg)

        return mdict, edict


    def _known_datatype(s, datatype):
        ''' checks if the given datatype is known to the database object '''

        # iterate over the datatypes in the reverse datatypes dict
        for k in s._rev_datatypes.keys():
            if _equivalent_datatype(datatype, k):
                return True
        return False


    def drop_model(s, modelname):
        ''' drops the model with the given name from the database '''

        if not modelname in s.models:
            raise _exceptions.NoSuchModelError("A model with name {:s} does not exist".format(modelname))

        rowid = s.modelrows[modelname]
        tablename = s.models[modelname].tabledef.name

        # first, check if this model is a dependency of another model
        q = '''SELECT modelname_
                FROM _fieldinfo_
                JOIN '''+MODELTBLNAME+'''
                ON _fieldinfo_.modeltable_ == '''+MODELTBLNAME+'''.table_
                WHERE _fieldinfo_.maps_to_ == ?
                OR _fieldinfo_.points_to_ == ?
                '''

        # make sure it all happens or not at all
        started_transaction = s.begin_transaction()

        s.dbcur.execute(q, (tablename, tablename))
        res = s.dbcur.fetchone()
        if res is not None:
            # NOTE: exception terminates transaction, which is ok
            if started_transaction is True:
                s.rollback_transaction()
                raise ValueError("I refuse: Model is dependency of {:s}".format(str(res)))

        # remove the mapping tables associated with this model
        q = 'SELECT mapping_table_ FROM _fieldinfo_ WHERE modelname_ == ?'
        s.dbcur.execute(q, (modelname,))
        droplist = [r[0] for r in s.dbcur if r[0] is not None]
        for tbl in droplist:
            q = 'DELETE FROM '+MAPTBLNAME+' WHERE maptable_ == ?'
            s.dbcur.execute(q, (tbl,))
            s._drop_table(tbl)

        # remove the property tables associated with this model
        q = 'SELECT property_table_ FROM _fieldinfo_ WHERE modelname_ == ?'
        s.dbcur.execute(q, (modelname,))
        droplist = [r[0] for r in s.dbcur if r[0] is not None]
        for tbl in droplist:
            q = 'DELETE FROM '+MAPTBLNAME+' WHERE maptable_ == ?'
            s.dbcur.execute(q, (tbl,))
            s._drop_table(tbl)

        # remove the field descriptors
        q = 'DELETE FROM '+FIELDTBLNAME+' WHERE modelid_ == ?'
        s.dbcur.execute(q, (rowid,))

        # remove the model
        q = 'DELETE FROM '+MODELTBLNAME+' WHERE id_ == ?'
        s.dbcur.execute(q, (rowid,))

        # remove the model table
        s._drop_table(tablename)

        # and remove the model from the models
        discard = s.models.pop(modelname)

        # re-create the timeline view
        _create_timeline_view(s)

        if started_transaction is True:
            s.dbcur.execute('COMMIT')


    def make_modelitem(s, modelname, **kwargs):
        ''' creates a modelitem for given modelname using kwargs

        Note: fields that are not given are set to None '''

        if not modelname in s.models:
            raise _exceptions.NoSuchModelError('A model with name {:s} is not yet registered'.format(modelname))

        # get the modelclass as registered with the database
        mclass = s.models[modelname].modelclass
        # and the fielddescriptors
        fds = s.models[modelname].fielddescriptors

        # check if illegal arguments where given
        for arg in kwargs:
            if arg not in mclass._fields:
                raise ValueError('field {:} not in model {:}'.format(arg, modelname))

        # check for illegal None values
        values = []
        for f in mclass._fields:
            val = kwargs.get(f, None)
            if fds[f].nullable is False and val is None:
                raise ValueError('field {:} may not be None'.format(f))
            values.append(val)

        return mclass(*values)


    def insert_modelitem(s, modelitem, cursor=None, nested=False):
        ''' inserts a single modelitem (and its subitems) into the appropriate
        table(s). If the modelitem is an integer, it is assumed to be the rowid
        of an already existing modelitem. In this case, the rowid is returned
        without any further checking (since we cannot possibly know which model
        this rowid relates to, without additional information).

        Note that this is a performance measure, since inserts of compound
        objects that consisted of recently inserted modelitems would lead to
        many needless queries on the database in order to determine the rowid
        of these items, while the caller already knows these rowids. But using
        this feature could also easily lead to mistakes when the caller does
        not properly track the rowids.
        '''

        # return the integer when modelitem is an int instead of a model object
        if isinstance(modelitem, int):
            return modelitem

        # check if writing is allowed
        modelname = type(modelitem).__name__
        if modelname not in s._writing_allowed:
            msg = 'writing of modelitems for model {:s} is not allowed until you register the model'
            msg = msg.format(modelname)
            raise _exceptions.ReadOnlyModelError(msg)

        try:
            inserter = s.models[modelname].inserter
        except:
            raise ValueError('could not retrieve insert function for '
                             'modelitem {:s}'.format(modelname))

        # make sure the insert as a whole is part of a transaction
        # (either started by us or an already active transaction)
        started_transaction = s.begin_transaction()
        try:
            rowid = inserter(s.dbcon, modelitem, nested)
        except:
            if started_transaction is True:
                s.rollback_transaction()
            raise

        if started_transaction is True:
            s.end_transaction()

        return rowid


    def hide_column_from_previews(s, fieldname, modelname=None):
        ''' hide column from compound fields in views '''

        if modelname is not None:
            modelid = s.modelrows[modelname]
            q = '''UPDATE {:s}
                   SET preview_ = 0
                   WHERE {:s}.name_ == ?
                   AND {:s}.modelid_ == ?
                '''

            q = q.format(FIELDTBLNAME, FIELDTBLNAME, FIELDTBLNAME)
            s.dbcur.execute(q, (fieldname, modelid))
        else:
            q = '''UPDATE {:s}
                   SET preview_ = 0
                   WHERE {:s}.name_ == ?
                '''
            q = q.format(FIELDTBLNAME, FIELDTBLNAME)
            s.dbcur.execute(q, (fieldname,))

        # update the model descriptors by reloading database
        s.reload_db()
        # and re-create the timeline view
        _create_timeline_view(s)


    def unhide_column_from_previews(s, fieldname, modelname=None):
        ''' show column in compound fields in views '''

        if modelname is not None:
            raise ValueError('not yet implemented')

        q = '''UPDATE '''+FIELDTBLNAME+ \
            ''' SET preview_ = 1 WHERE '''+FIELDTBLNAME+'''.name_ == ?'''

        s.dbcur.execute(q, (fieldname,))
        # update model descriptors by reloading database
        s.reload_db()
        # and re-create the timeline view
        _create_timeline_view(s)


    def modelitem(s, modelname, itemnr):
        ''' returns a single modelitem for the given model
        '''

        if modelname not in s.models:
            raise _exceptions.NoSuchModelError("A model with name {:s} does not exist".format(modelname))

        return s.models[modelname].getter(s.dbcon, itemnr)


    def isinstance(s, modelitem, modelname):
        ''' checks if given modelitem is an instance of model with given name '''

        if modelname not in s.models:
            raise _exceptions.NoSuchModelError("model with given name does not exist")

        return modelitem.__class__ == s.models[modelname].modelclass


    def delete_modelitem(s, modelname, itemnr):
        ''' deletes the given model_item, including the corresponding mapping
        table entries. Note that mapped items are not deleted themselves, since
        they might be references from some other modelitem or they may have
        been added individually earlier on. No way for us to know if the user
        want's to keep them or not. '''

        # use a dedicated cursor to prevent foobar in nested query scenario's
        cursor = s.dbcon.cursor()
        # start a transaction if not yet inside one
        started_transaction = s.begin_transaction()

        md = s.models[modelname]
        # only mapped fields and property fields are cleaned-up
        mfields = [k for k,v in md.fielddescriptors.items() if v.maptables != []]
        pfields = [k for k,v in md.fielddescriptors.items() if v.proptable != None]

        # cleanup the entries in the maptables with this id as left_id
        for f in mfields:
            for mtable in md.fielddescriptors[f].maptables:
                tblname = mtable.tabledef.name
                leftid = s.prefix+'leftid'
                q = 'DELETE FROM {:} WHERE {:} is ?'
                q = q.format(tblname, leftid)
                cursor.execute(q, (itemnr,))

        # cleanup the entries in the proptables with this id as left_id
        for f in pfields:
            ptable = md.fielddescriptors[f].proptable
            tblname = ptable.tabledef.name
            leftid = s.prefix+'leftid'
            q = 'DELETE FROM {:} WHERE {:} is ?'
            q = q.format(tblname, leftid)
            cursor.execute(q, (itemnr,))

        # cleanup the main record
        tblname = md.tabledef.name
        pkey = s.prefix+s.pkey
        q = 'DELETE FROM {:} WHERE {:} is ?'
        q = q.format(tblname, pkey)
        cursor.execute(q, (itemnr,))

        # all done
        if started_transaction is True:
            s.dbcur.execute('COMMIT')


    def modelitem_id(s, modelitem):
        ''' returns the id of a modelitem or None if it does not exist '''

        # get the model name
        modelname = type(modelitem).__name__

        if not modelname in s.models:
            raise _exceptions.NoSuchModelError('A model with name {:s} does not exist'.format(modelname))

        return s.models[modelname].identifier(s.dbcon, modelitem)


    def modelitems(s, modelname, with_pkey=False):
        ''' yields all modelitems for the given model '''

        if modelname not in s.models:
            raise _exceptions.NoSuchModelError('A model with name {:s} does not exist'.format(modelname))

        # iterate over the id's of the modelitems and yield results
        tblname = s.models[modelname].tabledef.name
        # do not provide cursor, which results in dedicated cursor
        rs = s.select(tblname, fields=(s.prefix+s.pkey,))

        # looping is safe, select uses dedicated cursor
        for r in rs:
            # r[0] is the pkey
            if with_pkey is True:
                yield (r[0], s.modelitem(modelname, r[0]))
            else:
                yield s.modelitem(modelname, r[0])


    def get_tblname(s, model):
        ''' return the tablename for the given model '''
        return s.models[model].tabledef.name


    def get_colname(s, model, field=None):
        ''' returns the column name for the given field in the given model.
        If field is None, the primary key name is returned as column name'''

        # table name
        tname = s.models[model].tabledef.name

        if field is None:
            return s.prefix+s.pkey

        # fieldname
        cdef = s.models[model].fielddescriptors[field].columndef
        if cdef is None:
            return None
        return cdef.name


    def get_maptable_names(s, model, field):
        ''' return the maptable name and its columnnames for the given field

        This is useful for allowing the caller to build complex queries based
        on his knowledge about the defined models, which should be more
        efficient than iterating over subitems
        '''

        # table name
        tname = s.models[model].tabledef.name

        # fieldname
        fdef = s.models[model].fielddescriptors[field]
        if len(fdef.maptables) == 0:
            return None

        for mt in fdef.maptables:
            n = mt.tabledef.name
            l = s.prefix+'leftid'
            r = s.prefix+'rightid'
            i = s.prefix+'element_index'
            yield _nt('maptable_names', 'table leftid rightid element_index')(n, l , r, i)


    def timeline(s, tstart=None, tend=None):
        ''' generate a sequence of modelitems in timeline order

        The timeline is optionally limited by the given tstart and/or tend
        '''

        if isinstance(tstart, _datetime):
            tstart = _isoformat(tstart)
        if isinstance(tend, _datetime):
            tend = _isoformat(tend)

        q = 'SELECT timestamp_, table_, {:s}id FROM {:s}Timeline_'.format(s.prefix, s.prefix)

        if isinstance(tstart, str):
            q+= ' WHERE timestamp_ >= "{:s}"'.format(tstart)

        if isinstance(tend, str):
            if isinstance(tstart, str):
                q+= ' AND '
            else:
                q+= ' WHERE '
            q+= 'timestamp_ <= "{:s}"'.format(tend)

        q+= ' ORDER BY timestamp_'

        cursor = s.dbcon.cursor()
        g = cursor.execute(q)

        tablecache = {}

        for tstamp, table, rowid in g:
            if table in tablecache:
                yield tstamp, s.modelitem(tablecache[table], rowid)
            else:
                for m in s.models.values():
                    if m.tabledef.name == table:
                        tablecache[table] = m.name
                        break
                yield tstamp, s.modelitem(m.name, rowid)


    def _has_model(s, model):
        ''' return True if the given model is already registered '''

        if model.name not in s.models:
            return False
        else:
            return model.equivalent(s.models[model.name])


    def _load_models(s):
        ''' loads all models from the database into s.models '''

        # expand to list for nested queries
        rs = list(s.select(MODELTBLNAME, fields=['name_'], cursor=s.dbcur))
        for r in rs:
            name = getattr(r, 'name_')
            if name in s.models:
                # this model is already registered, legal due to recursive
                # nature of _load_model
                continue
            s._load_model(name)


    def _load_model(s, name):
        ''' reads a model from the model table and add it to the models
        dictionary '''

        # read the model metadata from the model table
        r = list(s.select(MODELTBLNAME, where={'name_':name}, cursor=s.dbcur))
        if len(r) == 0:
            raise _exceptions.NoSuchModelError("A model with name {:s} does not exist".format(name))
            return None
        elif len(r) > 1:
            print(r)
            raise RuntimeError("multiple models with the same name: impossible!")

        # if we get here, we have the record that stores the model definition
        model_record = r[0]

        # get the field definitions by the id_ of the model
        # order by id_ within the fieldtable to maintain field order
        field_records = list(s.select(FIELDTBLNAME,
                                      where={'modelid_':model_record.id_},
                                      cursor=s.dbcur, orderby='id_'))

        # store the field_definitions in a list
        fdefs = []
        # and keep track of the submodels and subenums
        submodels = {}
        subenums = {}

        for field_record in field_records:
            datatype = field_record.datatype_
            nullable = bool(getattr(field_record, 'nullable_'))
            multiple = bool(getattr(field_record, 'multiple_'))
            submodel = getattr(field_record, 'submodel_')
            enum_ = getattr(field_record, 'enum_')
            preview = bool(getattr(field_record, 'preview_'))

            if field_record.datatype_ is not None:
                # the field contains a single normal datatype
                datatype = s.datatypes[field_record.datatype_].class_

            elif field_record.enum_ is not None:
                # the field contains a reference to an enum
                ename = list(s.select(ENUMTBLNAME,
                                      fields=['name_'],
                                      where={'id_':field_record.enum_},
                                      cursor=s.dbcur))
                if len(ename) != 1:
                    raise ValueError('expected exactly one name for enum')
                ename = getattr(ename[0], 'name_')
                # get the datatype
                datatype = s.enums[ename].enum
                subenums[ename] = s.enums[ename]

            elif field_record.submodel_ is not None:
                # the field contains a reference to another model
                mname = list(s.select(MODELTBLNAME,
                                      fields=['name_'],
                                      where={'id_':field_record.submodel_},
                                      cursor=s.dbcur))
                if len(mname) != 1:
                    raise ValueError('expected exactly one name for model')
                mname = getattr(mname[0],'name_')
                # check if the model is already in s.models
                if mname not in s.models:
                    # insert into global model dict
                    s._load_model(mname)
                # add to this models submodels dict
                submodels[mname] = s.models[mname]
                datatype = s.models[mname].modelclass

            # if colname is None, we have a mapped model/enum field or a
            # property field.
            elif field_record.colname_ is None:

                # first check if we are dealing with a property field
                # or a mapped model field

                pf = list(s.select(PROPTBLNAME, where={'field_':field_record.id_}, cursor=s.dbcur))
                # then check if we are dealing with a mapped field
                mfs = list(s.select(MAPTBLNAME, where={'field_':field_record.id_}, cursor=s.dbcur))

                # sanity check: either a property or a mapped field
                if len(pf) != 0 and len(mfs) != 0:
                    raise ValueError('expected either property or mapped field')

                # sanity check: non-uniform property or mapped field not allowed
                if len(pf) > 1 or len(mfs) > 1:
                    raise ValueError('only a single property or mapped field allowed')

                # we have a property field
                if len(pf) == 1:
                    datatype = getattr(pf[0], 'datatype_')
                    datatype = s.datatypes[datatype].class_

                # we have a mapped model or enum field
                if len(mfs) == 1:
                    mf = mfs[0]

                    mapped_enum = getattr(mf, 'enum_')
                    mapped_model = getattr(mf, 'model_')

                    if mapped_enum is not None:
                        # the field contains a reference to an enum, get its name
                        ename = list(s.select(ENUMTBLNAME, fields=['name_'],
                                     where={'id_':mapped_enum}, cursor=s.dbcur))
                        if len(ename) != 1:
                            raise ValueError('expected exactly one name for enum')
                        ename = getattr(ename[0], 'name_')
                        # get the datatype
                        datatype = s.enums[ename].enum
                        subenums[ename] = s.enums[ename]

                    elif mapped_model is not None:
                        # the field contains a reference to another model, get its name
                        mname = list(s.select(MODELTBLNAME, fields=['name_'],
                                     where={'id_':mapped_model}, cursor=s.dbcur))
                        if len(mname) != 1:
                            raise ValueError('expected exactly one name for model')
                        mname = getattr(mname[0], 'name_')
                        # check if the model is already in s.models
                        if mname not in s.models:
                            # insert into global model dict
                            s._load_model(mname)
                        # add to this models submodels dict
                        submodels[mname] = s.models[mname]
                        datatype = s.models[mname].modelclass

                    else:
                        raise ValueError("either enum or model should be set")

                # place in a tuple to indicate this is a multi-field
                datatype = (datatype,)

            else:
                raise ValueError("unhandled case in _load_model")

            # create the field_definition from the collected info
            fdef = _field_definition(field_record.name_, datatype, nullable, preview)
            # check if derived 'multiple' property matches stored one
            if fdef.multiple != multiple:
                raise ValueError('mistake in _field_definition function')
            # add the field definition to the dict of field defs
            fdefs.append(fdef)

        # create the model
        mdef = _model_definition(name, fdefs, 
                                 model_record.source_, model_record.version_,
                                 bool(model_record.explicit_dedup_),
                                 bool(model_record.implicit_dedup_),
                                 bool(model_record.fail_on_dup_))

        model = _Model(mdef, s.pkey, s.prefix, model_record.table_prefix_,
                model_record.field_prefix_,
                       s.datatypes, submodels=submodels, subenums=subenums)

        # store the models rowid
        s.modelrows[name] = model_record.id_

        if name not in s.models:
            s.models[name]=model
            s._register_table(model.tabledef, create=False)
            # add the required property and mapping tables to s.tables
            fields_with_proptable = list(filter(lambda fd: fd.proptable != None,
                                                model.fielddescriptors.values()))
            fields_with_maptables = list(filter(lambda fd: fd.maptables != [],
                                                model.fielddescriptors.values()))
            if len(fields_with_proptable) > 0:
                for fwp in fields_with_proptable:
                    s._register_table(fwp.proptable.tabledef, create=False)

            if len(fields_with_maptables) > 0:
                for fwm in fields_with_maptables:
                    for mt in fwm.maptables:
                        s._register_table(mt.tabledef, create=False)

        return model


    def _create_model_tables(s, model, create=True):
        ''' creates the required tables to hold the modeldata '''

        # NOTE: no need for transaction, all _register_table functions call
        # _create_table, which operate on dedicated cursors, and the PRAGMA
        # query used to check if table exists does not break transactions

        # first register and create the model table
        s._register_table(model.tabledef, create)

        # collect the lists of maptables for each of the fields that require
        # one or more maptables and put the individual tabledefs in a list
        maptbls = [fd.maptables for fd in model.fielddescriptors.values() if len(fd.maptables) != 0]
        maptbls = [md.tabledef for mds in maptbls for md in mds]
        # In order to maintain the creation order upon multiple executions,
        # sort the maptables by name prior creation. Since the tbl objects are
        # named tuples of which the first element is the name, we can just use
        # sort on the list of tabledefinitions
        maptbls.sort()

        # create the maptables
        for mt in maptbls:
            s._register_table(mt, create)

        # and create the property tables (sort by name first)
        proptbls = [fd.proptable.tabledef for fd in model.fielddescriptors.values() if
                    fd.proptable is not None]
        proptbls.sort()
        for pt in proptbls:
            s._register_table(pt, create)


    def _insert_model_metadata(s, model, modelrow):
        ''' fills the metadata tables related to a single model '''

        # put everything in single transaction
        started_transaction = s.begin_transaction()

        modelname = model.name

        for fieldname, fd in model.fielddescriptors.items():
            colname = None
            enumrow = None
            submodelrow = None
            if fd.columndef is not None:
                colname = fd.columndef.name
            if fd.subenum is not None:
                enumrow = s.enums[fd.subenum.__name__].rowid
            if fd.submodel is not None:
                submodelrow = s.modelrows[fd.submodel.__name__]

            # insert the record in the field table
            rec = s.tables[FIELDTBLNAME].record
            rec = rec(None, modelrow, fd.name, colname, fd.datatype,
                      fd.nullable, fd.multiple, submodelrow, enumrow,
                      fd.preview)
            fieldrow = s._insert_record(FIELDTBLNAME, rec, cursor=s.dbcur)

            # create entries for the mapping tables
            # first sort by name to make insertion order deterministic
            mt_by_name = sorted([(mt.tabledef.name, mt) for mt in fd.maptables])

            for (mtname, mt) in mt_by_name:
                subenumrow = None
                submodelrow = None
                if mt.enumtype is not None:
                    # we have a mapping table for an enum
                    subenumrow = s.enums[mt.enumtype].rowid
                elif mt.modeltype is not None:
                    # we have a mapping table for a model
                    submodelrow = s.modelrows[mt.modeltype]
                else:
                    raise ValueError("either enumtype or modeltype should be set")

                # insert the record in the maptable table
                rec = s.tables[MAPTBLNAME].record
                rec = rec(fieldrow, mtname, subenumrow, submodelrow)
                rowid = s._insert_record(MAPTBLNAME, rec, cursor=s.dbcur)

            # create an entry in the model_property table
            if fd.proptable is not None:
                ptname = fd.proptable.tabledef.name

                # insert record in the proptable table
                rec = s.tables[PROPTBLNAME].record
                rec = rec(fieldrow, fd.proptable.datatype, ptname)
                rowid = s._insert_record(PROPTBLNAME, rec, cursor=s.dbcur)

        if started_transaction is True:
            s.dbcur.execute('COMMIT')
