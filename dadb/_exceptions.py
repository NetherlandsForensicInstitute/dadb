''' exceptions.py - DADB specific exceptions.

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

class DadbError(Exception):
    ''' base class for other package exceptions '''
    pass


class ModelDefinitionError(DadbError):
    ''' Raised when a mistake is found in a model definition '''
    pass


class FieldDefinitionError(DadbError):
    ''' Raised when a mistake is found in a field definition '''
    pass


class VersionError(DadbError):
    ''' Raised when attempting to load a DADB database of incompatible version '''
    pass


class ExplicitDuplicateError(DadbError):
    ''' Raised when a duplicate is inserted explicitly and allow_dups is False '''
    pass


class ImplicitDuplicateError(DadbError):
    ''' Raised when a duplicate is inserted implicitly and allow_dups is False '''
    pass


class InconsistencyError(DadbError):
    ''' Raised when another model or enum with same name exists '''
    pass


class UnsatisfiedDependencyError(DadbError):
    ''' Raised when a required model or enum is not yet registered '''
    pass


class NonSeekableDataError(DadbError):
    ''' Raised when an attempt is made to seek in non-seekable data '''
    pass


class NoSuchModelError(DadbError):
    ''' Raised when a modelitem is requested for a non-existent model '''
    pass


class NoSuchModelItemError(DadbError):
    ''' Raised when a modelitem is requested that does not exist '''
    pass


class ReadOnlyModelError(DadbError):
    ''' Raised when attempting to add a modelitem when writing is not allowed '''
    pass


class InvalidArgumentError(DadbError):
    ''' Raised when the arguments to a function are invalid '''
    pass


class ToolNotAvailableError(DadbError):
    ''' Raised when a required tool is not available '''
    pass


class AssumptionBrokenError(DadbError):
    ''' raised when we are working with an assumption that is proven wrong '''
    pass


class OnlySupportedOnLinuxError(DadbError):
    ''' raised when we are not running on Linux system '''
    pass


class NoSuchDataObjectError(DadbError):
    ''' raised when a Data object with given id is not available '''
    pass
