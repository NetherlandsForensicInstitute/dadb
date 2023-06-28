''' _datatype.py - data type definitions and helper functions for DADB

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

# global imports
from datetime import date as _date
from dateutil import parser as _dateutilparser
from collections import namedtuple as _nt
from datetime import datetime as _datetime
from datetime import timedelta as _timedelta
from math import isnan as _isnan
from math import nan as _nan
import hashlib as _hashlib
from enum import EnumMeta as _EnumMeta
import types as _types
from io import IOBase as _IOBase
from functools import partial as _partial

# package imports
from ._data import Data as _Data
from ._exceptions import NonSeekableDataError as _NonSeekableDataError
from ._exceptions import InvalidArgumentError as _InvalidArgumentError


# datatype descriptor
typedesc = _nt('datatype', 'name class_ affinity convert revert')


# dictionary of datatype descriptors by name
basictypes = {'Datetime':  typedesc('Datetime', _datetime, 'TEXT',
                                    lambda v: isoformat(v),
                                    lambda v: from_iso8601(v)),
              'Date':      typedesc('Date', _date, 'TEXT',
                                    lambda v: isoformat(v),
                                    lambda v: from_iso8601(v)),
              'Integer':   typedesc('Integer', int, 'INTEGER',
                                    lambda v: intconv(v),
                                    lambda v: intrev(v)),
              'String':    typedesc('String', str, 'TEXT',
                                    lambda v: stringconv(v),
                                    lambda v: stringrev(v)),
              'Bytes':     typedesc('Bytes', bytes, 'BLOB',
                                    lambda v: bytesconv(v),
                                    lambda v: bytesrev(v)),
              'Bool':     typedesc('Bool', bool, 'INTEGER',
                                   lambda v: boolconv(v),
                                   lambda v: boolrev(v)),
              # timedelta is stored in milliseconds
              'TimeDelta': typedesc('TimeDelta', _timedelta, 'REAL',
                                    lambda v: timedeltaconv(v),
                                    lambda v: timedeltarev(v)),
              'Float':     typedesc('Float', float, 'REAL',
                                    lambda v: floatconv(v),
                                    lambda v: floatrev(v)),
              # this affinity is cosmetic, all values will be NULL
              'NULL':      typedesc('NULL', type(None), 'INTEGER',
                                    lambda v: v,
                                    lambda v: v)
             }


def stringconv(s):
    ''' typecheck and convert string for storing into database '''

    if s is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif type(s) is str:
        return s
    raise _InvalidArgumentError("invald type passed to converter")


def stringrev(s):
    ''' typecheck and convert retrieved value to string '''

    if s is None:
        raise _InvalidArgumentError("NULL value passed through reverter")
    elif type(s) == bytes:
        # we have seen cases where a string was stored as BLOB internally and
        # when reading back this value it will be a bytes object.
        # For now raise an exception when this occurs so we can think of a way
        # to deal with this.
        raise RuntimeError("Not yet implemented: string was stored as BLOB")
    elif type(s) == str:
        return s
    raise _InvalidArgumentError("invald type passed to reverter")


def bytesconv(s):
    ''' typecheck and convert bytes for storing into database '''

    if s is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif isinstance(s, bytes):
        return s
    raise _InvalidArgumentError("invald type passed to converter")


def bytesrev(s):
    ''' typecheck and convert retrieved value to bytes '''

    if s is None:
        raise _InvalidArgumentError("NULL value passed through reverter")
    elif isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        # A BLOB might be stored as TEXT which results in a string object being
        # returned. For now raise an exception when this occurs so we can think
        # of a way to deal with this.
        raise RuntimeError("Not yet implemented: bytes was stored as TEXT")
    raise _InvalidArgumentError("invald type passed to reverter")


def isoformat(timeobj):
    ''' typecheck date or datetime and convert to iso8601 for storing as TEXT '''

    if timeobj is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif hasattr(timeobj, 'isoformat'):
        return timeobj.isoformat()
    raise _InvalidArgumentError("invald type passed to converter")


def from_iso8601(string):
    ''' typecheck iso8601 string and convert back to date or datetime '''

    if string is None:
        raise _InvalidArgumentError("NULL value passed through reverter")
    elif not isinstance(string, str):
        raise _InvalidArgumentError("invald type passed to converter")
    elif 'T' in string:
        return _dateutilparser.parse(string)
    elif '-' in string:
        # special case that is not handled the way I want by dateutil
        y,m,d = string.split('-')
        return _date(int(y),int(m),int(d))
    raise _InvalidArgumentError("invald type passed to reverter")


def intconv(i):
    ''' typecheck integer for storing in database '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif not isinstance(i, int):
        raise _InvalidArgumentError("invald type passed to converter")
    if abs(i) > 2**63-1:
        # in this case, the user want's to store a large integer that can
        # not be represented in the INTEGER storage class in SQLite. We've
        # used conversion to bytes here, but this can present problems
        # with integer size and signing. Note that when converting the int
        # directly to string, we might end up with a lossy conversion, due
        # to the NUMERIC affinity of integer colums. To prevent this, we
        # convert to hex string.

        # WARNING: this might lead to mixed-data types in these columns, which
        # presents problem when the user accesses the database directly (i.e.
        # via queries). It is recommended to use the DADB API to access
        # DADB databases for this reason.
        return hex(i)
    else:
        return i


def intrev(i):
    ''' typecheck and convert sqlite stored value back to integer '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through reverter")
    elif isinstance(i, str):
        # convert back from hex string
        return int(i, 16)
    elif isinstance(i, int):
        return i
    raise _InvalidArgumentError("invald type passed to reverter")


def boolconv(i):
    ''' typecheck and convert boolean to int for storing as INTEGER '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif isinstance(i, bool):
        return int(i)
    raise _InvalidArgumentError("invald type passed to converter")


def boolrev(i):
    ''' typecheck and convert int to boolean '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through reverter")
    elif isinstance(i, int):
        return bool(i)
    raise _InvalidArgumentError("invald type passed to reverter")


def floatconv(i):
    ''' typecheck and convert float for storing in sqlite database '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif isinstance(i, float):
        if _isnan(i):
            return 'NaN'
        else:
            return i
    raise _InvalidArgumentError("invald type passed to converter")


def floatrev(i):
    ''' convert stored float, allowing for NaN '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif i == 'NaN':
        return _nan
    elif isinstance(i, float):
        return i
    raise _InvalidArgumentError("invald type passed to reverter")


def timedeltaconv(i):
    ''' convert timedelta to total_seconds for storing in database '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif isinstance(i, _timedelta):
        return i.total_seconds()
    raise _InvalidArgumentError("invald type passed to converter")


def timedeltarev(i):
    ''' convert total seconds back to timedelta again '''

    if i is None:
        raise _InvalidArgumentError("NULL value passed through converter")
    elif isinstance(i, float) or isinstance(i, int):
        return _timedelta(seconds=i)
    raise _InvalidArgumentError("invald type passed to reverter")


def equivalent_datatype(item1, item2):
    ''' compare two models, enums or simple datatypes.

    Depending on the origin of an enum or model (namedtuple class), the
    underlying object may be different, even if all fields and the name are
    equal. This function is used to check equality in such cases '''

    if item1 == item2:
        # this is for 'basic' types
        return True

    if type(item1) != type(item2):
        # the meta-type of both types must be equal (EnumMeta, Class)
        return False

    # NOTE: this construct is needed when two identical Enums are
    # created separately (i.e. they are syntactically equal, but have
    # a different id). DO NOT REMOVE!
    if type(item1) == _EnumMeta and type(item2) == _EnumMeta:
        # name and all name,value pairs must be equal
        if item1.__name__ != item2.__name__:
            return False
        i1 = sorted([(c[1].name, c[1].value) for c in item1.__members__.items()])
        i2 = sorted([(c[1].name, c[1].value) for c in item2.__members__.items()])
        return i1 == i2

    # NOTE: see note above, this is for named tuples
    if hasattr(item1, '_fields') and hasattr(item2, '_fields'):
        # name and all fields must be equal
        if item1.__name__ != item2.__name__:
            return False
        return sorted(item1._fields) == sorted(item2._fields)

    return False


def equal(m1, m2):
    ''' return True if the two provided items are equal

    The provided items m1 and m2 can be of many different types, as used
    throughout this package. Some comparisons are more complex or
    time-consuming than others, so the checks are organize in such a manner
    that we try to prove non-equality as quickly as possible. In order to
    compare subfields, the equal function is called recursively. This means
    that the comparison should also work when subfields are (sequences of)
    complex objects.

    The following constraints apply:

    - if any of the two provided items is a generator, we simply cannot compare
      them without consuming the items. This is problematic when the items must
      still be processed by the caller, so we cannot check equality. In this
      case the function returns False (non-equal). It's best if the caller
      provides a partial generator function instead, so the generator can be
      restarted by the caller after this equality check.

    - when sequences are to be compared, they should be tuples (not lists)

    - empty sequences are considered equal to the value None

    - partial generators are called and the items are compared in-order until a
      difference is found. For generators that yield a large result set with no
      differences or differences occuring at the end, this may take a long
      time.

    - partial generators can be compared to tuples and are considered
      equal if the resulting sequence of items is equal to sequence in the
      provided tuple

    - partial generator functions that result in an empty sequence are
      considered equal to the value None

    - enum values are considered equal if their type is equivalent and their
      value is equal

    - modelitems (or any namedtuple) are considered equal if they have the same
      named fields (not necessarily in the same order) and if the datatypes of
      the values stored in each fields are equal and if their value is equal.

    - modelitems that have some form of IOBase derived object in one or more of
      their fields are only compared in these fields when all other fields
      dismisses non-equality. The rationale for this is that the comparison of
      the actual data might be time-consuming

    - items that both have the type Data, as used in this package, are compared
      by their sha256

    - IOBase derived objects are fully hashed (sha256) in order to compare
      them
    '''

    # generators can not be compared without consuming the elements
    if type(m1) == _types.GeneratorType or type(m2) == _types.GeneratorType:
        raise _InvalidArgumentError("equal function does not accept GeneratorType items")
        #return False

    # we only accept tuples (immutable) not lists
    if type(m1) == list or type(m2) == list:
        raise _InvalidArgumentError("equal function does not accept lists")

    # empty sequences are considered equal to None
    if type(m1) == tuple and m2 is None:
        if len(m1) == 0:
            return True
        else:
            return False
    if type(m2) == tuple and m1 is None:
        if len(m1) == 0:
            return True
        else:
            return False

    # empty partial generators are considered equal to None
    if type(m1) == _partial and m2 is None:
        try:
            next(m1())
            return False
        except StopIteration:
            return True
    if type(m2) == _partial and m1 is None:
        try:
            next(m2())
            return False
        except StopIteration:
            return True

    # compare tuples
    if type(m1) == tuple and type(m2) == tuple:
        # both are tuples, length should match
        if len(m1) != len(m2):
            return False
        for a,b in zip(m1, m2):
            if not equal(a,b):
                return False
        return True

    # compare partial generators
    if type(m1) == _partial and type(m2) == _partial:
        g1 = m1()
        g2 = m2()
        for a,b in zip(g1, g2):
            if not equal(a,b):
                return False
        # if we get here, the shortest generator is exhausted,
        # so both must be exhausted for equality
        try:
            a = next(g1)
            return False
        except StopIteration:
            pass
        try:
            b = next(g2)
            return False
        except StopIteration:
            pass
        return True

    # compare tuple to partial generator
    tpl, gen = None, None
    if type(m1) == tuple and type(m2) == _partial:
        tpl = m1
        gen = m2()
    elif type(m2) == tuple and type(m1) == _partial:
        tpl = m2
        gen = m1()
    # do the actual comparion
    if (tpl, gen) != (None, None):
        c = 0
        for a,b in zip(tpl, gen):
            if not equal(a,b):
                return False
            c+=1
        if len(tpl) == c:
            # tuple 'exhausted', generator should also be exhausted
            try:
                a = next(gen)
                return False
            except StopIteration:
                return True
        else:
            # generator is exhausted, tuple not yet
            return False

    # if provided values are enums, they must be equivalent and equal
    if type(type(m1)) == _EnumMeta and type(type(m2)) == _EnumMeta:
        if not equivalent_datatype(type(m1), type(m2)):
            return False
        return m1.value == m2.value

    # if provided values are modelitems, they must be equivalent and equal
    # NOTE: if the order of fields differ, but all values are equal, we
    # still consider this a duplicate. So stick to sort-order of m1 when
    # dealing with elements from m2 (using getattr and m1._fields)
    if hasattr(m1, '_fields') and hasattr(m2, '_fields'):
        if not equivalent_datatype(type(m1), type(m2)):
            return False
        # IOBase derived classes are expensive to compare, so save these
        # for the case where all other fields are equal.
        io_standoff = []
        for f in m1._fields:
            v1 = getattr(m1, f)
            v2 = getattr(m2, f)
            if isinstance(v1, _IOBase) or isinstance(v2, _IOBase):
                io_standoff.append((v1, v2))
            elif not equal(v1, v2):
                return False
        # iterate through the IOBase derived fields
        for v1, v2 in io_standoff:
            if not equal(v1, v2):
                return False
        return True

    # both provided values are of type 'Data', compare sha256
    if type(m1) == _Data and type(m2) == _Data:
        return m1.sha256 == m2.sha256

    # one value is a fileobject (i.e. BufferedReader) and other is None,
    # which is considerd equal if size of fileobject is 0
    if m1 is None and isinstance(m2, _IOBase):
        if m2.seekable() is True:
            m2.seek(0,2)
            sz = m2.tell()
            m2.seek(0)
            return sz == 0
        elif hasattr(m2, 'peek'):
            # some IOBase derived objects  have a peek method, use this to
            # determine size without advancing position
            return len(m2.peek()) == 0
        else:
            raise _NonSeekableDataError('equality-check cannot proceed, due to non-seekable file-object')
    if m2 is None and isinstance(m1, _IOBase):
        if m1.seekable() is True:
            m1.seek(0,2)
            sz = m1.tell()
            m1.seek(0)
            return sz == 0
        elif hasattr(m1, 'peek'):
            # some IOBase derived objects  have a peek method, use this to
            # determine size without advancing position
            return len(m1.peek()) == 0
        else:
            raise _NonSeekableDataError('equality-check cannot proceed, due to non-seekable file-object')

    # one value is a fileobject (i.e. BufferedReader) and other 'Data'
    if type(m1) == _Data and isinstance(m2, _IOBase):
        # NOTE: we used to insert the data in the database, since this would
        # prevent having to read the file twice when the data was not yet
        # present, but for proper module isolation, it is not desirable that we
        # have to carry along a database object just for the sake of comparing
        # a Data object to a file-like object. So, in the worst case, we have
        # to read the file-like-object twice, when the comparison fails. I
        # think file-system cache will help us out here, tough...

        # hash the data in m2, but only if m2 is seekable
        if m2.seekable() is True:
            sha256 = _hash_file(m2)
            return m1.sha256 == sha256
        else:
            raise _NonSeekableDataError('equality-check cannot proceed, due to non-seekable file-object')
    elif type(m2) == _Data and isinstance(m1, _IOBase):
        if m1.seekable() is True:
            sha256 = _hash_file(m1)
            return sha256 == m2.sha256
        else:
            raise _NonSeekableDataError('equality-check cannot proceed, due to non-seekable file-object')
    elif isinstance(m2, _IOBase) and isinstance(m1, _IOBase):
        if m1.seekable() is True and m2.seekable() is True:
            return _hash_file(m1) == _hash_file(m2)
        else:
            raise _NonSeekableDataError('equality-check cannot proceed, due to non-seekable file-object')

    # if we get here, we are not dealing with sequences, enums or
    # modelitems, so we can directly compare the values
    return m1 == m2


def _hash_file(fileobj):
    ''' hash the data in the given fileobj '''

    sha256 = _hashlib.sha256()
    blocksize = 131072
    fileobj.seek(0)
    block = fileobj.read(blocksize)
    while len(block) > 0:
        sha256.update(block)
        block = fileobj.read(blocksize)
    return sha256.hexdigest()
