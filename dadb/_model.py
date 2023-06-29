''' model.py - Model object for dadb.

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

# global imports
from collections import namedtuple as _nt
from collections import OrderedDict as _OD
from enum import EnumMeta as _EnumMeta
from functools import partial as _partial
from io import IOBase as _IOBase
import apsw as _apsw
import types as _types
from mmap import mmap as _mmap

# package imports
from ._schema import col as _col
from ._schema import tbl as _tbl
from ._schema import validname as _validname
from ._datatype import equivalent_datatype as _equivalent_datatype
from ._datatype import equal as _equal
from ._exceptions import ExplicitDuplicateError as _ExplicitDuplicateError
from ._exceptions import ImplicitDuplicateError as _ImplicitDuplicateError
from ._exceptions import NoSuchModelItemError as _NoSuchModelItemError
from ._model_definition import mdef_t as _mdef_t
from ._model_definition import check_fielddefinition as _check_fielddefinition
from ._model_definition import equivalent_fielddescriptors as _equivalent_fielddescriptors
from ._model_definition import create_fielddescriptor as _create_fielddescriptor
from ._model_definition import convert_fielddefinitions as _convert_fielddefinitions


class Model:
    ''' class representing models in the DADB framework '''


    #######
    # API #
    #######


    def __init__(s, modeldef, pkey, dbprefix, table_prefix, fieldprefix,
                 datatypes, submodels=None, subenums=None):
        ''' initialize a model object '''

        s.name = modeldef.name
        s.fielddefinitions = modeldef.fielddefs
        s.source = modeldef.source
        s.version = modeldef.version
        s.explicit_dedup = bool(modeldef.explicit_dedup)
        s.implicit_dedup = bool(modeldef.implicit_dedup)
        s.fail_on_dup = bool(modeldef.fail_on_dup)
        s.submodels = submodels
        s.enums = subenums

        # properties of the database required for prefab queries
        # the primary key column
        s.pkey = pkey
        # database prefix
        s.dbprefix = dbprefix
        # prefix to add to the table names
        s.tableprefix = table_prefix
        # prefix to add between table_prefix and fieldname
        s.fieldprefix = fieldprefix
        # the datatypes
        s.datatypes = datatypes

        # check if fielddefinitions conforms to constraints
        for fdef in s.fielddefinitions:
            _check_fielddefinition(fdef)

        # initialize the modelclass
        s._init_modelclass()

        # initialize the fielddescriptors
        s._init_fielddescriptors()

        # initialize the table definition
        s._init_tabledef()

        # put the submodel, subenum, mapped, property, data and basic fields in separate dicts
        s._submodel_fields = {k:v for k,v in s.fielddescriptors.items() if v.submodel != None}
        s._enum_fields = {k:v for k,v in s.fielddescriptors.items() if v.subenum != None}
        s._mapped_fields = {k:v for k,v in s.fielddescriptors.items() if v.maptables != []}
        s._property_fields = {k:v for k,v in s.fielddescriptors.items() if v.proptable != None}
        # make special note of Data fields, since dealing with these is more expensive than
        # with fields that have other basic datatypes
        s._data_fields = {k:v for k,v in s.fielddescriptors.items() if v.datatype == 'Data'}
        # NOTE: _normal_fields includes the _data_fields !!
        s._normal_fields = {k:v for k,v in s.fielddescriptors.items() if v.datatype != None}

        # Prepare the query for the direct fields in the model (i.e. those fields that do
        # not require a property or mapping table and are stored directly in the model table, which
        # includes the enum and submodel fields, since these contain an integer pointing to the proper
        # modelitem or enum value). The result tuple contain the fields in the same order as defined
        # in the modelclass
        qfields = [f for f in s.modelclass._fields if f not in s._property_fields and f not in s._mapped_fields]
        s._direct_fields = qfields

        if len(qfields) == 0:
            # we need at least 1 field to be able to create a record
            raise ValueError('model {:} has no direct fields!'.format(s.name))
        else:
            # convert fieldnames to column names
            qfields = [s.dbprefix+s.fieldprefix+f for f in qfields]
            # convert to comma separated string
            qfield_string = ', '.join(qfields)
            # and construct the query from this
            q = '''SELECT {:} FROM {:} WHERE {:} == ? '''
            s._direct_field_query = q.format(qfield_string, s.tabledef.name, s.dbprefix+s.pkey)

        # prepare a query for inserting the direct fields in the model table
        qmarks = ",".join(["?"]*len(s._direct_fields))
        names = [s.fielddescriptors[n].columndef.name for n in s._direct_fields]
        names = ",".join(names)
        s._insert_query = '''INSERT INTO {:s}({:s}) VALUES ({:s});'''.format(s.tabledef.name, names, qmarks)

        # prepare a query for getting the id(s) of the modelitem(s) based on
        # the given direct fields, excluding any data fields
        qfields = [f for f in s.modelclass._fields if f not in s._property_fields
                   and f not in s._mapped_fields and f not in s._data_fields]
        # keep track of order of fields for unpacking results
        s._direct_id_query_fields = qfields
        if len(qfields) == 0:
            # this is not tested, so raise an exception
            raise ValueError('model {:} needs at least one field other than Data!'.format(s.name))
        else:
            # convert fieldnames to column names
            qfields = [s.dbprefix+s.fieldprefix+f for f in qfields]
            where = 'WHERE ' + ' AND '.join(['%s is ?' % n for n in qfields])
            s._direct_id_query = 'SELECT {:} FROM {:s} {:s};'.format(s.dbprefix+s.pkey, s.tabledef.name, where)

        # the mapped, property and data fields require more work to get the actual modelitem
        s._more_work_fields = [k for k in s._mapped_fields]
        s._more_work_fields.extend([k for k in s._property_fields])
        s._more_work_fields.extend([k for k in s._data_fields])

        # shortcut to the getter function for submodel fields
        s._getters = {k: s.submodels[v.submodel.__name__].getter for k,v in s._submodel_fields.items()}
        # shortcut for translating enum fields to enum values
        s._field_to_enum = {k: s.enums[v.subenum.__name__].enum for k,v in s._enum_fields.items()}

        # prepare dictionaries with convert and revert functions by field name, to prevent
        # multi-dict lookups for each database interaction
        s._field_converters = {k: s.datatypes[v.datatype].convert for k,v in s._normal_fields.items()}
        s._field_reverters = {k: s.datatypes[v.datatype].revert for k,v in s._normal_fields.items()}

        # prepare the query getting and inserting the values in property fields and the function to
        # revert from storageclass back to original data type
        s._property_queries = {}
        s._property_insert_queries = {}
        for fname, fdesc in s._property_fields.items():
            q = '''SELECT {:s} FROM {:s} WHERE {:s} == ? ORDER BY {:s}'''
            q = q.format(fdesc.proptable.tabledef.fields[1].name, fdesc.proptable.tabledef.name,
                         fdesc.proptable.tabledef.fields[0].name, fdesc.proptable.tabledef.fields[2].name)
            s._property_queries[fname] = q

            q = '''INSERT INTO {:s} VALUES (?,?,?);'''.format(fdesc.proptable.tabledef.name)
            s._property_insert_queries[fname] = q

            # the datatype is stored as subfield of the proptable field, add the reverter and converter
            s._field_converters[fname] = s.datatypes[fdesc.proptable.datatype].convert
            s._field_reverters[fname] = s.datatypes[fdesc.proptable.datatype].revert

        # prepare the query for getting the values in mapped fields that contain a
        # single enum (i.e. uniform) and for inserting them in the maptable
        s._mapped_enum_queries = {}
        s._mapped_enum_insert_queries = {}
        for fname, fdesc in s._mapped_fields.items():
            if len(fdesc.maptables) == 1 and fdesc.maptables[0].enumtype is not None:
                # field maps to a sequence of enum values of the same type
                # (i.e. multiple permissions for an installed application). We can
                # prepare a query for this scenario.
                q = '''SELECT {:s} FROM {:s} WHERE {:s} == ? ORDER BY {:s}'''
                q = q.format(fdesc.maptables[0].tabledef.fields[1].name, fdesc.maptables[0].tabledef.name,
                             fdesc.maptables[0].tabledef.fields[0].name, fdesc.maptables[0].tabledef.fields[2].name)
                s._mapped_enum_queries[fname] = q

                q = '''INSERT INTO {:s} VALUES (?,?,?);'''.format(fdesc.maptables[0].tabledef.name)
                s._mapped_enum_insert_queries[fname] = q

                # the field contains a single type of enum, add to field_to_enum dict
                s._field_to_enum[fname] = s.enums[fdesc.maptables[0].enumtype].enum

        # if a field uses a single mapping table, we can prepare a query for getting
        # the sequence of submodel_ids for that field. This allows us to compare a stored
        # modelitem with a provided model item that uses a sequence of primary keys of the
        # submodelitems, instead of full submodel items.
        s._mapped_model_queries = {}
        s._mapped_model_insert_queries = {}
        for fname, fdesc in s._mapped_fields.items():
            if len(fdesc.maptables) == 1 and fdesc.maptables[0].modeltype is not None:
                # this is only possible if the field is uniform
                s._mapped_model_queries[fname] = fdesc.maptables[0].query

                q = '''INSERT INTO {:s} VALUES (?,?,?);'''.format(fdesc.maptables[0].tabledef.name)
                s._mapped_model_insert_queries[fname] = q

            elif len(fdesc.maptables) != 1:
                raise ValueError("programming mistake, only 1 maptable expected")

        # create a list of sub_insert functions that need to be called
        # based on the types of mapped fields that are present
        s._subinserters = []
        if len(s._property_fields) != 0:
            s._subinserters.append(s._insert_property_fields)

        if len(s._mapped_enum_queries) != 0:
            s._subinserters.append(s._insert_mapped_enum_fields)

        if len(s._mapped_model_queries) != 0:
            s._subinserters.append(s._insert_mapped_model_fields)


    def identifier(s, dbcon, modelitem):
        ''' returns the id of the given modelitem if it exists '''

        # iterate over the direct fields in the modelitem, and create a
        # list of values (qvals) to use in the direct_id_query
        qvals = []
        for fieldname in s._direct_id_query_fields:

            if fieldname in s._submodel_fields:
                # 1) field is a submodel field
                subitem = getattr(modelitem, fieldname)
                if subitem is None:
                    # 1a) no submodel item provided, add None to query values
                    qvals.append(None)
                elif isinstance(subitem, int):
                    # 1b) submodel id provided, add id to query values
                    qvals.append(subitem)
                else:
                    # 1c) full submodel item provided, use identifier to get id
                    subid = s.submodels[type(subitem).__name__].identifier(dbcon, subitem)
                    if subid == None:
                        # the provided submodel item does not exist, no match!
                        return None
                    qvals.append(subid)

            elif fieldname in s._enum_fields:
                # 2) field is enum field, get integer value
                qvals.append(getattr(modelitem, fieldname).value)

            else:
                # 3) regular field (not Data), get db representation
                v = getattr(modelitem, fieldname)
                if v is None:
                    qvals.append(None)
                else:
                    # convert the field value to it's storage class representation
                    qvals.append(s._field_converters[fieldname](v))

        # execute the query
        c = dbcon.cursor()
        c.execute(s._direct_id_query, qvals)

        if len(s._more_work_fields) == 0:
            # if we have only direct fields, the first match is good enough!
            try:
                r = next(c)
                return r[0]
            except StopIteration:
                # no results, so no match!
                return None

        # if we get here, we have at least one record that mathes on the direct
        # query fields, but we also have at least one indirect_field, so we have
        # to do some more complex comparison in the remainder of this function.

        # the provided modelitem may have used a sequence of integers instead
        # of a sequence of modelitems. Check for these fields by checking if we
        # have a mapped_model_query.
        shortcut_fields = set()
        for fname in s._mapped_model_queries:
            # check the provided value
            provided_value = getattr(modelitem, fname)
            if isinstance(provided_value, tuple):
                types = list(set([type(v) for v in provided_value]))
                if len(types) == 1 and types[0] == int:
                    # yes, a tuple of integers was provided, we can simply
                    # compare this to the sequence of mapped items
                    shortcut_fields.add(fname)

        # iterate through matches for the direct fields, until we find a match
        # in the indirect fields as well
        for r in c:
            id_ = r[0]
            # get the modelitem with this id
            match = s.getter(dbcon, id_)
            # assume this is a match until proven otherwise
            match_ok = True
            # iterate over the indirect_fields and compare field by field
            for fname in s._more_work_fields:

                if fname in shortcut_fields:
                    # the field can be compared based on submodelitem id's
                    q = s._mapped_model_queries[fname]
                    sub_cursor = dbcon.cursor()
                    sub_results = sub_cursor.execute(q, (id_,))
                    # the mapped_model_query returns rightid in second field
                    sub_ids = tuple([sr[1] for sr in sub_results])
                    if provided_value != sub_ids:
                        # no match, break inner loop
                        match_ok = False
                        break

                else:
                    # fall back to full comparison of field value (more expensive)
                    match_val = getattr(match, fname)
                    modelitem_val = getattr(modelitem, fname)
                    if not _equal(getattr(match, fname), getattr(modelitem, fname)):
                        # no match, break inner loop
                        match_ok = False
                        break

            # if we get here, all indirect_fields have been compared, so if we
            # did not reject the match, we accept it as being equal
            if match_ok is True:
                return id_

        # if we get here, we have exhausted all direct field matches without finding full match
        return None


    def inserter(s, dbcon, modelitem, nested=False):
        ''' function to insert modelitems into the database '''

        # check the datatype of the provided modelitem
        if not _equivalent_datatype(type(modelitem), s.modelclass):
            raise ValueError('modelitem is incompatible with model {:s}'.format(s.name))

        # perform the appropriate duplicate checking (will raise error if
        # fail_on_dup is True and duplicate is inserted)
        existing_rowid = s._dupchecker(dbcon, modelitem, nested)
        if existing_rowid is not None:
            return existing_rowid

        # use a dedicated cursor for the insert
        cursor = dbcon.cursor()
        # insert the direct_fields
        rowid = s._insert_direct_fields(dbcon, modelitem)
        # run the various subinserter functions, if any
        for sub_inserter in s._subinserters:
            sub_inserter(dbcon, rowid, modelitem)
        return rowid


    def equivalent(s, other_model):
        ''' returns True if the provided other_model is equivalent to this one
        '''

        if s.name != other_model.name:
            return False

        if not _equivalent_datatype(s.modelclass, other_model.modelclass):
            return False

        if s.tableprefix != other_model.tableprefix:
            return False

        if s.fieldprefix != other_model.fieldprefix:
            return False

        if s.source != other_model.source:
            return False

        if s.version != other_model.version:
            return False

        if s.fail_on_dup != other_model.fail_on_dup:
            return False

        if s.implicit_dedup != other_model.implicit_dedup:
            return False

        if s.tabledef != other_model.tabledef:
            return False

        # other values (i.e. subenums, submodels) are ultimately derived from
        # the fielddescriptors, so just compare these

        return _equivalent_fielddescriptors(s.fielddescriptors,
                                            other_model.fielddescriptors)


    def getter(s, dbcon, itemnr):
        ''' return the modelitem with the given id utilizing the given database connection '''

        # use a dedicated cursor to prevent issues when used in nested queries
        cursor = dbcon.cursor()

        # execute the direct field query for this model with the given modelitem id
        res = list(cursor.execute(s._direct_field_query, (itemnr,)))

        if len(res) == 0:
            raise _NoSuchModelItemError("No modelitem {:s} exists with id {:d}".format(s.name, itemnr))
        elif len(res) != 1:
            raise ValueError("table corruption, multiple items with same ID")
        res = res[0]

        # Next step is to convert everything back to the original modelclass,
        # which involves mapping table fields onto the model fields, converting
        # to the original datatype and resolving submodels, subenums,
        # properties and mapped enums/models.

        values = []
        direct_idx = 0

        # iterate over the fields and insert the value into the values list
        for mf in s.modelclass._fields:

            # 1) property field
            if mf in s._property_fields:
                # return the prepared query on a dedicated cursor
                q = s._property_queries[mf]
                subcur = dbcon.cursor()
                subcur.execute(q, (itemnr,))
                # fetch results as a tuple and convert values back to original datatype
                values.append(tuple([s._field_reverters[mf](p[0]) for p in subcur]))
                subcur.close()

            # 2) mapped enum or model
            elif mf in s._mapped_fields:

                # 2a) sequence of enum values
                if mf in s._mapped_enum_queries:
                    # run the prepared query on a dedicated cursor
                    q = s._mapped_enum_queries[mf]
                    subcur = dbcon.cursor()
                    subcur.execute(q, (itemnr,))
                    # fetch results, convert to enum value and add to values as tuple
                    values.append(tuple([s._field_to_enum[mf](r[0]) for r in subcur]))
                    subcur.close()

                # 2b) sequence of model items
                else:
                    # these are not pre-fetched, but instead a partial function
                    # is returned that the caller can call to generate a
                    # sequence of items multiple times
                    values.append(_partial(s._mapper, dbcon, itemnr, mf))

            # 3) directly stored field values
            else:
                # get the value from the direct query results at current index
                v = res[direct_idx]
                # increment te direct field index for next iteration
                direct_idx+=1

                # 3a) Enum field
                if mf in s._enum_fields:
                    # translate enum integer to actual enum value
                    values.append(s._field_to_enum[mf](v))

                # 3b) submodel field
                elif mf in s._submodel_fields:
                    # substitute object id with actual modelitem
                    if v is not None:
                        # call the getter function of the submodel
                        values.append(s._getters[mf](dbcon, v))
                    else:
                        values.append(None)

                # 3c) basic datatype field
                else:
                    # convert back using the revert function
                    if v is not None:
                        values.append(s._field_reverters[mf](v))
                    else:
                        values.append(None)

        # convert result to modelclass and return
        return s.modelclass(*values)


    def allow_duplicate_inserts(s):
        ''' allow insertion of duplicates to speed up inserts when caller knows
        that it will not insert duplicates. This only alters the value of the
        in-memory model; it is not written to the database, so next time when
        you load the database the defaults will apply. '''

        # if explicit_dedup is True, the model_definition enforces that
        # implicit_dedup is also True and that fail_on_dup is False. This means
        # that there is no use disabling fail_on_dup for these models.
        if s.explicit_dedup is True:
            raise ValueError("allow_duplicate_inserts not allowed for model: {:}".format(s.name))

        if s.fail_on_dup is False:
            raise ValueError("logical mistake by caller, fail_on_dup already False: {:}".format(s.name))

        s.fail_on_dup = False


    def deny_duplicate_inserts(s):
        ''' deny insertion of duplicates (which comes at a performance
        penalty) temporarily. This only alters the value of the in-memory
        model; it is not written to the database, so next time when you load
        the database the defaults will apply. '''

        if s.explicit_dedup is True:
            raise ValueError("deny_duplicate_inserts not allowed for model: {:}".format(s.name))

        if s.fail_on_dup is True:
            raise ValueError("logical mistake by caller, fail_on_dup already True: {:}".format(s.name))

        s.fail_on_dup = True


    ######################
    # internal functions #
    ######################


    def _init_modelclass(s):
        ''' takes the fielddefinitions and stores the modelclass from these definitions '''

        # if any of the fielddefinitions contain a modeldefinition, it should
        # be converted to a modelclass before proceeding, which allows a user
        # to only have to define models, not actually create them before registration
        s.fielddefinitions = _convert_fielddefinitions(s.fielddefinitions)

        # create the modelclass from the name and the fielddefinitions
        s.modelclass = _nt(s.name, ' '.join([k.name for k in s.fielddefinitions]))


    def _init_fielddescriptors(s):
        ''' initialize the fielddescriptors '''

        # put the fielddescriptors in a OrderedDict to maintain definition order
        fielddescriptors = _OD()

        for fielddef in s.fielddefinitions:
            fdesc = _create_fielddescriptor(s.name, fielddef, s.datatypes,
                                         s.fieldprefix, s.tableprefix, s.dbprefix)
            fielddescriptors[fielddef.name]=fdesc

        s.fielddescriptors = fielddescriptors


    def _init_tabledef(s):
        ''' initialize table definition '''

        # create table definition
        pkey_name = _validname(s.pkey, s.dbprefix)
        # we can now construct the table definition using the basic fields
        tablename = _validname(s.name, s.tableprefix)
        # we add the prefix to the tablename only, the columndefinitions in the
        # fielddescriptors already have this set properly
        tablename = _validname(tablename, s.dbprefix)

        # we add an extra field for the primary key column
        coldefs = [_col(pkey_name, 'autogenerated', 'INTEGER PRIMARY KEY AUTOINCREMENT')]
        # define remaining columns in same order as fielddescriptor dict
        coldefs = coldefs + [fd.columndef for fd in s.fielddescriptors.values() if fd.columndef is not None]

        # The rationale for not adding UNIQUE constraints in order to prevent
        # insertion of duplicate entries where all fields match is the
        # following: The UNIQUE constraint in SQLite does not hold for NULL
        # fields (or rather: all NULL values are considered unique). The
        # alternative, to only consider fields that are never NULL is no
        # option, because uniqueness might not be defined by only those
        # columns. Instead deduplication upon insertion is dealth with in
        # Python code (in the _dupchecker function), depending on the model
        # settings.

        s.tabledef = _tbl(tablename, 'autogenerated', coldefs, None)


    def _sanity_check(s):
        ''' sanity checks after model initialization '''

        # the total of all the fields should match the modelclasses' fieldcount
        mappedfields = len([fd.maptables for fd in s.fielddescriptors.values() if len(fd.maptables) != 0])
        propfields = len([fd.proptable for fd in s.fielddescriptors.values() if fd.proptable is not None])
        # we do not count the pkey field, hence the minus 1
        defined = len(s.tabledef.fields) - 1 + mappedfields + propfields
        if defined != len(s.modelclass._fields):
            raise ValueError('not all fields accounted for')


    def _mapper(s, dbcon, itemnr, fieldname):
        ''' helper function that deals with the mappings for mapped models '''


        # collect modeltype, modelid by its element_index order in a dict
        yieldorder = {}
        for mapdescriptor in s._mapped_fields[fieldname].maptables:

            if mapdescriptor.modeltype is None:
                raise ValueError('mapper function is intended for mapped model fields')

            if mapdescriptor.enumtype is not None:
                raise ValueError('mapper function is not intended for mapped enum fields')

            # run the prepared query to for this maptable
            # NOTE: Using a dedicated cursor here is important, since this will
            # be added as partial to modelitems, and we can't hope to keep
            # track of cursor usage when user is iterating over modelitems and
            # updating the database and so on. So hide this from user and play
            # it safe!
            subcur = dbcon.cursor()
            subcur.execute(mapdescriptor.query, (itemnr,))

            # iterate over the results so we can yield them in order and so we
            # exhaust the query before launching a new one, which might lead to
            # incomplete results.
            for r in subcur:
                if r[2] in yieldorder:
                    raise ValueError("duplicate element_index")
                yieldorder[r[2]] = (mapdescriptor.modeltype, r[1])

        # now that we know in which order to yield results, start the generator
        # which performs a single (set of) query/ies (via the getter) upon each
        # call to next()
        for element_index in sorted(yieldorder.keys()):
            mtype, mid = yieldorder[element_index]
            yield s.submodels[mtype].getter(dbcon, mid)


    def _insert_direct_fields(s, dbcon, modelitem):
        ''' collect and insert the direct fields for given modelitem, returning rowid '''

        # list to hold the direct_field values in proper order
        direct_values = []

        # iterate over each of the direct_fields and handle each value
        # according to the datatype of the field.
        for fname in s._direct_fields:

            # get the value in the given field
            fval = getattr(modelitem, fname)

            # 0) value NONE is provided (NULL)
            if fval is None:
                if s.fielddescriptors[fname].nullable is True:
                    # add None to the record, which will be a NULL value in the database
                    direct_values.append(None)
                else:
                    raise ValueError("value None given in non-nullable field '{:s}'".format(fname))

            # 1) value is an Enum
            elif fname in s._enum_fields:
                # make sure datatype of provided value is correct
                if not _equivalent_datatype(type(fval), s._enum_fields[fname].subenum):
                    msg = 'Expected type {:} in field {:}, got {:}'
                    msg = msg.format(s._enum_fields[fname].subenum, fname, type(fval))
                    raise ValueError(msg)
                # add the integer value to the record
                direct_values.append(fval.value)

            # 2) value is a submodel item
            elif fname in s._submodel_fields:

                # get the model name
                submodel_name = s._submodel_fields[fname].submodel.__name__

                # 2a) rowid was provided
                if isinstance(fval, int):
                    # check if modelitem with that id exists
                    # NOTE: this could be something to disable when the caller
                    #       knows that it uses recently inserted submodelitems.
                    #       For now, no premature optimization.
                    try:
                        s.submodels[submodel_name].getter(dbcon, fval)
                    except _NoSuchModelItemError:
                        msg = "no modelitem of type {:} exists with id {:} for field {:}"
                        msg = msg.format(submodel_name, fval, fname)
                        raise _NoSuchModelItemError(msg)
                    # add the rowid to the record
                    direct_values.append(fval)

                # 2b) submodelitem provided (inserter will check datatype)
                else:
                    # insert the submodel item (nested=True, implicit insert)
                    rowid = s.submodels[submodel_name].inserter(dbcon, fval, True)
                    direct_values.append(rowid)

            # 3) normal field with a basic datatype value
            elif fname in s._normal_fields:

                # we do not accept any sequences or generator types
                if type(fval) in (tuple, _types.GeneratorType):
                    raise ValueError('value provided in field {:s} may not be a sequence'.format(fname))

                # this field contains a simple value, store by using
                # the appropriate converter for the type at hand
                datatype_name = s._normal_fields[fname].datatype

                # make sure datatype of provided value matches modeldescriptor
                if not _equivalent_datatype(type(fval), s.datatypes[datatype_name].class_):

                    # allow IOBase and mmap objects in Data fields
                    if isinstance(fval, _IOBase) and datatype_name == 'Data':
                        pass
                    elif isinstance(fval, _mmap) and datatype_name == 'Data':
                        pass
                    else:
                        msg = 'datatype {:} of provided value for field {:s} does not match required type {:s}'
                        msg = msg.format(type(fval), fname, datatype_name)
                        raise ValueError(msg)

                # provided value has proper datatype, convert to storage class
                # and add to values NOTE: the convert function of the 'Data'
                # datatype already inserts the data into the database and
                # returns the rowid of the data object, which is then added to
                # the list of direct fields. Because we use the same database
                # connection, all the required inserts are part of the same
                # transaction, so if some other field fails, the data is also
                # not inserted, making a single modelitem insert atomic.
                sval = s._field_converters[fname](fval)
                direct_values.append(sval)

        # now that all direct fields are resolved, we can insert the modelitem.
        cursor = dbcon.cursor()
        cursor.execute(s._insert_query, tuple(direct_values))
        rowid = dbcon.last_insert_rowid()
        return rowid


    def _insert_property_fields(s, dbcon, rowid, modelitem):
        ''' collect and insert the fields that require a property table '''

        # use a dedicated cursor for the insert
        cursor = dbcon.cursor()

        # iterate over the property fieldnames
        for fname, insert_query in s._property_insert_queries.items():

            expected_datatype_name = s._property_fields[fname].proptable.datatype
            expected_datatype = s.datatypes[expected_datatype_name].class_
            converter = s._field_converters[fname]

            # get the provided value
            fval = getattr(modelitem, fname)

            # we only accept a sequence in property fields
            if type(fval) not in (tuple, _types.GeneratorType):
                raise ValueError('value provided in field {:s} should be a sequence'.format(fname))

            # iterate over the sequence and insert the proptable entries
            for element_index, subval in enumerate(fval):

                # check for the proper datatype
                if not _equivalent_datatype(type(subval), expected_datatype):
                    msg = 'value provided in field {:s} should have datatype {:s}'.format(fname, expected_datatype_name)
                    raise ValueError(msg)

                # convert the value and insert into the property table (no
                # deduplication is done, sequence may contain duplicates)
                cursor.execute(insert_query, (rowid, converter(subval), element_index))


    def _insert_mapped_enum_fields(s, dbcon, rowid, modelitem):
        ''' collect and insert mapped enum fields '''

        # use a dedicated cursor for the insert
        cursor = dbcon.cursor()

        # iterate over the mapped enum fieldnames
        for fname, insert_query in s._mapped_enum_insert_queries.items():

            expected_enumtype_name = s._mapped_fields[fname].maptables[0].enumtype

            # get the provided value which should either be a tuple or a
            # generator function (no partial function allowed, contrary to the
            # _insert_mapped_model_fields function, since a numeric sequence is
            # less expensive to keep in memory than a sequence of modelitems
            # with arbitrary subfields; so we can simply expand to a tuple
            # prior to the call if the generator may not be exhausted by the
            # insert).
            fval = getattr(modelitem, fname)

            # we only accept a sequence or generator
            if type(fval) not in (tuple, _types.GeneratorType):
                raise ValueError('value provided in field {:s} should be a sequence'.format(fname))

            # iterate over the sequence and insert the mapped enum entries
            for element_index, subval in enumerate(fval):

                # only enum values accepted
                if type(type(subval)) != _EnumMeta:
                    raise ValueError('all items in field {:s} should be Enum'.format(fname))
                if type(subval).__name__ != expected_enumtype_name:
                    raise ValueError('incorrect enum type in field {:s}'.format(fname))

                # convert the enum to its numeric value and insert into the maptable
                cursor.execute(insert_query, (rowid, subval.value, element_index))


    def _insert_mapped_model_fields(s, dbcon, rowid, modelitem):
        ''' collect and insert mapped uniform model fields '''

        # use a dedicated cursor for the insert
        cursor = dbcon.cursor()

        # iterate over the mapped model fields
        for fname, insert_query in s._mapped_model_insert_queries.items():

            # get the name of the modeltype in this mapped field
            expected_modeltype_name = s._mapped_fields[fname].maptables[0].modeltype

            # as an optimization, the provided modelitem may contain a sequence
            # of objectIDs of existing modelitems in the mapped_model_field. If
            # this is the case, then *all* the items in the sequence should be
            # objectIDs instead of full modelitems. If the first element in the
            # sequence is an objectID, this variable is set to True.
            numeric_insert = False

            # get the provided value, which should either be a tuple or a
            # generator function (or a partial function that can be called to
            # obtain the generator function).
            fval = getattr(modelitem, fname)

            # if the value is a partial function, run it to get the generator
            if type(fval) == _partial:
                fval = fval()

            # we only accept a sequence or generators in mapped fields
            if type(fval) not in (tuple, _types.GeneratorType):
                raise ValueError('value provided in field {:s} should be a sequence'.format(fname))

            # iterate over the sequence and insert the mapped entries
            for element_index, subval in enumerate(fval):

                # 1) Numeric value (objectID)
                if isinstance(subval, int):
                    if element_index == 0:
                        # enable numeric_insert if first element is numeric
                        numeric_insert = True
                    elif numeric_insert is False:
                        # This is not the first element, and the value is
                        # numeric, but numeric_insert was not set to True. This
                        # means that the provided sequence mixes objectIDs and
                        # full modelitems, which is not allowed.
                        msg = "attempt to mix numeric and full modelitem inserts in field {:s}"
                        raise ValueError(msg.format(fname))
                    # if we get here, this is an allowed numeric_insert
                    try:
                        # check if the item with given objectID exists
                        # NOTE: here too, we could disable this check if the
                        #       caller knows that the objectIDs are indeed
                        #       present, because they where just inserted by
                        #       the same caller. For now leave this extra
                        #       check in place.
                        s.submodels[expected_modeltype_name].getter(dbcon, subval)
                    except _NoSuchModelItemError:
                        msg = "no modelitem of type {:} exists with id {:} for field {:}"
                        msg = msg.format(expected_modeltype_name, subval, fname)
                        raise _NoSuchModelItemError(msg)
                    # the id is valid, insert the maptable entry
                    cursor.execute(insert_query, (rowid, subval, element_index))

                # 2) Modelitem value
                elif hasattr(type(subval), '_fields'):
                    if numeric_insert is True:
                        # apparently, the first element was numeric, and some
                        # other element was not. This is not allowed
                        msg = "attempt to mix numeric and full modelitem inserts in field {:s}"
                        raise ValueError(msg.format(fname))
                    if type(subval).__name__ != expected_modeltype_name:
                        # NOTE: we only check name here, the inserter called below checks proper class
                        raise ValueError('incorrect modelitem type in field {:s}'.format(fname))
                    # Use the inserter of the submodel item type to insert the
                    # subitem, set nested to True since this insert is done as
                    # part of another modelitem insert.
                    subid = s.submodels[expected_modeltype_name].inserter(dbcon, subval, True)
                    # insert the maptable entry
                    cursor.execute(insert_query, (rowid, subid, element_index))

                else:
                    # we only accept integers or modelitems
                    raise ValueError('incorrect modelitem type in field {:s}'.format(fname))


    def _dupchecker(s, dbcon, modelitem, nested=False):
        ''' performs the appropriate duplication check, but only if it really
        has to, since performing a lookup for each insert is expensive! '''

        # NOTE: the identifier will become slower when more records are added,
        # so when the user of a model already knows that the fields are
        # discriminating enough and it takes care to prevent inserting
        # duplicates itself, set fail_on_dup and explicit_dedup to False

        exp_msg = 'duplicate exists with id {:}, explicit insert denied'
        imp_msg = 'duplicate exists with id {:}, implicit insert denied'

        if nested is False:
            # explicit insert
            if s.explicit_dedup is False and s.fail_on_dup is False:
                # never mind dups
                return None
            if s.explicit_dedup is True:
                # deduplicate
                existing = s.identifier(dbcon, modelitem)
                if existing is not None:
                    return existing
                else:
                    return None
            # we never get here if explicit_dedup is True
            if s.fail_on_dup is True:
                # fail on duplicate
                existing = s.identifier(dbcon, modelitem)
                if existing is not None:
                    raise _ExplicitDuplicateError(exp_msg.format(existing))
                else:
                    return None
            else:
                raise RuntimeError('this should not happen!')

        # if we get here, nested is True and this is an implicit insert

        if s.implicit_dedup is False and s.fail_on_dup is False:
            # never mind dups
            return None
        elif s.implicit_dedup is True:
            # deduplicate
            existing = s.identifier(dbcon, modelitem)
            if existing is not None:
                return existing
            else:
                return None
        # we never get here if implicit_dedup is True
        elif s.fail_on_dup is True:
            # fail on duplicate
            existing = s.identifier(dbcon, modelitem)
            if existing is not None:
                raise _ImplicitDuplicateError(imp_msg.format(existing))
            else:
                return None

        raise RuntimeError('we should not get here!')
