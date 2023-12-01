''' fileparentmodel.py - model linking a file to its parent file

Copyright (c) 2023 Netherlands Forensic Institute - MIT License
'''

import os as _os

from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import Data as _Data
from .. import exceptions as _exceptions
from .. import progresswrapper as _progresswrapper
from . import filemodel as _fmodel


##########
# MODELS #
##########

# changelog:
# 1 - initial model version

MODELNAME = 'fileparent'
MODELDESCRIPTION = 'fileparent model for DADB'
MODELVERSION = 1

modeldef = _model_def(MODELNAME,
                      [_field_def('child', _fmodel.modeldef, nullable=False, preview=True),
                       _field_def('parent', _fmodel.modeldef, nullable=False)],
                       MODELDESCRIPTION, MODELVERSION,
                       fail_on_dup=True)


#######
# API #
#######


def register_with_db(db):
    ''' register this model to the given database '''
    _fmodel.register_with_db(db)
    db.register_model(modeldef)


def insert(db, child, parent, skip_checks=False):
    ''' insert a child-parent relation in the fileparent model

    Arguments:
    - db          : the database
    - child       : the (rowid of the) child
    - parent      : the (rowid of the) parent
    - skip_checks : when True, expensive checks (i.e. loopchecking) is skipped

    The checks are expensive due to the many queries required to detect if a
    relationship insert would cause a loop. Therefore, when the caller is sure
    that a proper hierarchy is inserted, these checks can be skipped.
    '''

    # these consistency checks are expensive and can be optionally skipped
    if skip_checks is False:
        # convert modelitems to their rowids
        if db.isinstance(child, _fmodel.MODELNAME):
            child = db.modelitem_id(child)
        if db.isinstance(parent, _fmodel.MODELNAME):
            parent = db.modelitem_id(parent)

        # a child can not be its own parent
        if child == parent:
            raise ValueError("A file can not be it's own parent")

        # first check if the relation already exists
        res = _already_has_parent(db, child)
        if res is not None:
            if res[1] == parent:
                return res[0]
            else:
                raise ValueError("file {:} already has a parent {:}".format(child, res[1]))

        # When adding a child, we must prevent adding a circular relationship.
        # This occurs when the child itself is a parent, and the parent we are
        # trying to link to the child occurs in it's own subtree. I.e.
        # 1 -> 2 -> 3 -> 4 -> 1
        #
        # check if the child occurs somewhere in the parent-hierarchy of the parent
        for p in _walk_up_tree(db, parent):
            if p == child:
                raise ValueError("adding {:} as parent of {:} would create a loop".format(parent, child))

    # if we get here, we can safely insert the relationship while maintaining
    # a tree-structure in the hierarchy (or we skipped these checks)
    m = db.make_modelitem(MODELNAME, child=child, parent=parent)
    rowid = db.insert_modelitem(m)
    return rowid


def insert_files(db, files, root=None, progress=False):
    ''' update the fileparent relations for the given sequence of files

    Note that the sequence of files should contain an actual file-hierarchy of
    some sorts.  Adding a random sequence of files might lead to incorrect
    results. The parent-relations are determined based on the path property of
    the files in the set.

    Arguments:

    - db       : the database to operate on
    - files    : a sequence of (rowids of) already existing file items
    - root     : (rowid of) an already existing file
    - progress : if True, show progressbar

    If root is given, all files without a parent are rooted onto this node. If
    root is not given, only a single file may exist with no parent in the
    hierarchy, which is automatically considered to be the root of the tree.
    '''

    # check if model is registered before doing any work
    db.check_registered(MODELNAME)

    # get the file id of the provided root
    provided_root_id = _fileid(db, root)

    # we are not sure if directories are always physically earlier in the
    # fileset so first iterate over the entire set of extracted files and keep
    # track of all directories and build two dictionaries, one with the path of
    # dirs mapped to their ids, and the other that maps a basename to a
    # sequence of children ids. In addition, keep track of all encountered file ids
    directories, child_dict, all_ids = _directory_info(db, files, progress=progress)

    # determine the root directory (fileid) of a set of unrooted directories
    rootdir_id, rootdir_path = _determine_rootdir(directories, child_dict)

    if rootdir_id is None and root is None:
        raise ValueError("rootdir could not be determined, provide root directory!")

    if rootdir_path is not None and rootdir_path not in directories:
        raise ValueError("programming mistake in building dict of directories")

    # if we get here, we can proceed to insert the hierarchy
    # wrap everything in a single transaction
    started_transaction = db.begin_transaction()

    if provided_root_id is not None and rootdir_id is not None:
        # add a relation between the detected rootdir and the provided root dir
        insert(db, rootdir_id, provided_root_id, skip_checks=True)

    for dirname, subids in child_dict.items():

        if dirname is None:
            # this indicates we had a root directory with the path separator as path
            # check if we have the rootdir_id as only subitem
            if subids != [rootdir_id]:
                if started_transaction is True:
                    db.rollback_transaction()
                raise ValueError("incorrect list of subids for dirname None")
            # this subitem is not rooted, consider processed and remove from set
            all_ids.remove(rootdir_id)

        elif dirname in directories:
            dir_id = directories[dirname]
            # these files are rooted under a known directory
            for subid in subids:
                try:
                    # insert the relationship, no need to check for loops,
                    # (expensive) since we are dealing with a hierarchy
                    insert(db, subid, dir_id, skip_checks=True)
                except _exceptions.ExplicitDuplicateError:
                    # this simply means we already have this relation, ok!
                    pass
                except:
                    # all other exceptions are raised
                    if started_transaction is True:
                        db.rollback_transaction()
                    raise
                all_ids.remove(subid)

        elif dirname == '':
            # the files or directories in the list of subids are unrooted
            # make provided root it's parent
            for subid in subids:
                try:
                    # insert the relationship, no need to check for loops,
                    # (expensive) since we are dealing with a hierarchy
                    insert(db, subid, provided_root_id, skip_checks=True)
                except _exceptions.ExplicitDuplicateError:
                    # this simply means we already have this relation, ok!
                    pass
                except:
                    # all other exceptions are raised
                    if started_transaction is True:
                        db.rollback_transaction()
                    raise
                all_ids.remove(subid)

        else:
            if started_transaction is True:
                db.rollback_transaction()
            raise ValueError("inconsistency in child_dict and directories dict")

    if len(all_ids) != 0:
        # there are orphans and/or gaps in the hierarchy
        if started_transaction is True:
            db.rollback_transaction()
        raise ValueError("the sequence does not contain a strict file hierarchy. Aborted!")


    # if we get here, it seem to have worked out okay
    if started_transaction is True:
        db.end_transaction()


def get_parent(db, file_, with_pkey=False):
    ''' returns the parent for the given file modelitem (or None) '''

    # we use direct query, check if models exists
    db.check_registered(MODELNAME)
    db.check_registered(_fmodel.MODELNAME)

    if isinstance(file_, int):
        fid = file_
    else:
        fid = db.modelitem_id(file_)

    q = _parent_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (fid,))
    res = list(c)
    if len(res) > 1:
        raise ValueError('error: file has multiple parents')
    elif len(res) == 0:
        # if we cannot find a parent, make sure this is not caused by lack of
        # any fileparent records
        if not _do_fileparent_records_exist:
            raise ValueError('no fileparent records exist yet')
        return None
    elif res[0][0] is None:
        # file has no parent
        return None
    else:
        pid = res[0][0]

    if with_pkey is True:
        return pid, db.modelitem(_fmodel.MODELNAME, pid)
    else:
        return db.modelitem(_fmodel.MODELNAME, pid)


def get_children(db, file_, with_pkey=False):
    ''' returns iterator over all children of a given file '''

    if isinstance(file_, int):
        fid = file_
    else:
        fid = db.modelitem_id(file_)

    q = _children_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (fid,))
    res = list(c)

    for child in res:
        cid = child[0]
        if with_pkey is True:
            yield (cid, db.modelitem(_fmodel.MODELNAME, cid))
        else:
            yield db.modelitem(_fmodel.MODELNAME, cid)


def get_tree(db, file_):
    ''' return tree for given file as list of files or ids, starting at root.

    If the given file is a fileobject, the return value will be a list of file
    objects, if the given file is the id of a file object, the return value
    will be a list of ids.
    '''

    if isinstance(file_, int):
        path = list(_walk_up_tree(db, file_))
        path.reverse()
        path.append(file_)
        return path
    else:
        fileid = db.modelitem_id(file_)
        path = list(_walk_up_tree(db, fileid))
        path = [_fmodel.get(db, i) for i in path]
        path.reverse()
        path.append(file_)
        return path


def walk(db, top, with_pkey=False):
    ''' directory tree generator, similar to os.walk

    For each directory in the directory tree rooted at top, yields a 3-tuple

    dirpath, dirnames, filenames

    dirpath is the full path of the current directory object, dirnames is a
    list of the names of the subdirectories in dirpath, filenames is a list of
    the names of the non-directory files in dirpath.

    The tree is traversed topdown. The top argument may also be a file that has
    children (i.e. an archive), but any further archives are treated as normal
    files.

    If with_pkey is True: the path and the names are returned as 2-tuples

    primary_key, name

    here name is the path or name and primary_key is the id of the file object
    in the filemodel table.
    '''

    if hasattr(top, 'name'):
        # a filemodel object has been passed, get id if we need it
        if with_pkey is True:
            topid = db.modelitem_id(top)
    elif isinstance(top, int):
        topid = top
        top = _fmodel.get(db, topid)
    elif isinstance(top, tuple):
        # allow (id, fileobj) to prevent extra db query in recursion
        topid, top = top

    # get the children
    children = get_children(db, topid, True)

    dirs = []
    files = []

    for c in children:
        if c[1].ftype.value == _fmodel.Filetype.directory.value:
            dirs.append((c[0], c[1]))
        else:
            files.append((c[0], c[1].name))

    if with_pkey is True:
        yield ((topid, top.path), [(d[0],d[1].name) for d in dirs], [(f[0],f[1]) for f in files])
    else:
        yield (top.path, [d[1] for d in dirs], [f[1] for f in files])

    for d in dirs:
        for c in walk(db, d, with_pkey=with_pkey):
            yield c


####################
# helper functions #
####################

_GETPARENT_QUERY = None
_GETCHILDREN_QUERY = None
_GETPARENT_RECORD_QUERY = None


def _walk_up_tree(db, fileid):
    ''' yields all parent id's until root is reached '''

    # NOTE: this might hit max recursion level for deep trees.

    res = _already_has_parent(db, fileid)
    if res is None:
        # nothing left to yield
        return
    else:
        # yield parentid
        yield res[1]
        for r in _walk_up_tree(db, res[1]):
            yield r


def _children_query(db):
    ''' constructs (or fetches from cache) query to get children for parent '''

    # use cached version if available
    global _GETCHILDREN_QUERY
    if _GETCHILDREN_QUERY is not None:
        return _GETCHILDREN_QUERY

    tbl = db.get_tblname(MODELNAME)
    ccol = db.get_colname(MODELNAME, 'child')
    pcol = db.get_colname(MODELNAME, 'parent')
    q = '''SELECT {:s}
           FROM {:s}
           WHERE {:s} == ?'''

    q = q.format(ccol, tbl, pcol)
    _GETCHILDREN_QUERY = q
    return _GETCHILDREN_QUERY


def _parent_query(db):
    ''' constructs (or fetches from cache) query to get parent of a child '''

    # use cached version if available
    global _GETPARENT_QUERY
    if _GETPARENT_QUERY is not None:
        return _GETPARENT_QUERY

    tbl = db.get_tblname(MODELNAME)
    ccol = db.get_colname(MODELNAME, 'child')
    pcol = db.get_colname(MODELNAME, 'parent')
    q = '''SELECT {:s}
           FROM {:s}
           WHERE {:s} == ?'''

    q = q.format(pcol, tbl, ccol)
    _GETPARENT_QUERY = q
    return _GETPARENT_QUERY


def _do_fileparent_records_exist(db):
    ''' checks if any fileparent records exist '''

    q = ''' SELECT count(*) FROM {:s}fileparent '''
    q = q.format(db.prefix)
    c = db.dbcon.cursor()
    c.execute(q)
    r = c.fetchall()
    if r[0][0] == 0:
        return False
    return True


def _parent_record_query(db):
    ''' constructs (or fetches from cache) query to get fileparent record for a child '''

    # use cached version if available
    global _GETPARENT_RECORD_QUERY
    if _GETPARENT_RECORD_QUERY is not None:
        return _GETPARENT_RECORD_QUERY

    tbl = db.get_tblname(MODELNAME)
    ccol = db.get_colname(MODELNAME, 'child')
    q = '''SELECT *
           FROM {:s}
           WHERE {:s} == ?'''

    q = q.format(tbl, ccol)
    _GETPARENT_RECORD_QUERY = q
    return _GETPARENT_RECORD_QUERY


def _already_has_parent(db, file_):
    ''' returns rowid, parent_id tuple if file already has parent in fileparent model '''

    if isinstance(file_, int):
        fid = file_
    else:
        raise ValueError("wrong argument")

    q = _parent_record_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (fid,))
    res = list(c)
    if len(res) > 1:
        raise ValueError('error: file has multiple parents')
    elif len(res) == 0:
        # if we cannot find a parent, make sure this is not caused by lack of
        # any fileparent records
        if not _do_fileparent_records_exist:
            raise ValueError('no fileparent records exist yet')
        return None
    else:
        rowid, child, parent = res[0]
        return (rowid, parent)


def _fileid(db, root):
    ''' return file id of provided root, which can be a file object or a file id '''

    if root is None:
        return None

    # accept file id or file object as root argument
    if isinstance(root, int):
        root_id = root
        # will raise Exception if non-existant
        root = db.modelitem(_fmodel.MODELNAME, root_id)
    elif db.isinstance(root, _fmodel.MODELNAME):
        root_id = db.modelitem_id(root)
    else:
        raise ValueError("provide (id of) existing file")

    return root_id


def _directory_info(db, files, progress=False):
    ''' iterate over all files and collect info on directories needed to build a hierarchy '''

    if progress is True:
        files = _progresswrapper(files, '{:20s}'.format('    fileparent'))

    # we are not sure if directories are always physically earlier in the
    # fileset so first iterate over the entire set of extracted files and keep
    # track of all directories and build two dictionaries, one with the path of
    # dirs mapped to their ids, and the other that maps a basename to a
    # sequence of children ids.
    directories = {}
    child_dict = {}
    # keep track of all encountered id's to make sure we do not have any orphans
    all_ids = set()
    all_files = {}

    # we accept a sequence of file items or a sequence of rowids, but not mixed
    # so keep track of whether or not we have seen an integer in the sequence
    numeric_insert = False
    model_insert = False

    for file_ in files:
        if isinstance(file_, int):
            if model_insert is True:
                raise ValueError("cannot mix rowid and modelitems in sequence of files")
            numeric_insert = True
            fileid = file_
            # raises exception if non-existent
            file_ = db.modelitem(_fmodel.MODELNAME, fileid)
        elif db.isinstance(file_, _fmodel.MODELNAME):
            if numeric_insert is True:
                raise ValueError("cannot mix rowid and modelitems in sequence of files")
            model_insert = True
            try:
                fileid = db.modelitem_id(file_)
            except _exceptions._NoSuchModelItemError:
                raise ValueError("provide existing file items in file sequence")
        else:
            raise ValueError("provide either rowids or file items in files sequence")

        all_ids.add(fileid)
        all_files[file_.path]=fileid

        if file_.ftype.value == _fmodel.Filetype.directory.value:
            # we have a directory
            if file_.path == _os.path.sep:
                # do not strip of trailing slash in this case, we are probably dealing with
                # the root directory '/'
                mypath = file_.path
                # NOTE: setting myparent to None indicates that the path is the root
                myparent = None
            else:
                mypath = file_.path.rstrip(_os.path.sep)
                # NOTE: if the file path has no separators (either trailing or leading),
                #       the parent will be '', which is valid for some sources (i.e. archives)
                myparent = _os.path.dirname(mypath)

            if mypath in directories:
                raise ValueError("duplicate directory name encountered: {:}".format(mypath))

            directories[mypath] = fileid

        else:
            # we have a different type of file
            if file_.path == _os.path.sep:
                raise ValueError("expected {:s} to be a directory".format(file_.path))

            mypath = file_.path.rstrip(_os.path.sep)
            myparent = _os.path.dirname(mypath)

        # now, regardless of whether this is a directory or some other
        # type of file, record under which directory the file lives
        if myparent in child_dict:
            child_dict[myparent].append(fileid)
        else:
            child_dict[myparent] = [fileid]

    # if the set of files is a proper hierarchy that doesn't start at '/' the
    # child_dict will contain an entry for the parent of the directory that is
    # the actual root (i.e. if the file set has /home/user as root, the
    # child_dict will contain '/home' as well). This happens when we import a
    # fileset, for example. In this case we should not include this directory
    # in the child_dict, since it is not actually part of the set of files.
    # Instead, we should remove all paths that are not part of the set of files
    # from the child_dict and instead combine the children of these
    # non-existant files in a single list of children of the 'None' parent
    rootparent = None
    rootid = None

    for p, children in child_dict.items():
        if p not in all_files:
            if p is None or p == '':
                # this is the case if we have the path separator as root,
                # or if the files originate from an archive without trailing separator
                continue
            # if we get here, we have a parent that is not in the fileset
            # so we are probably dealing with an imported fileset from a directory.
            # this should happen only once and we should have only 1 child (the rootdir)
            if rootparent is not None:
                raise ValueError("expected only a single parent of the root")
            if len(children) != 1:
                raise ValueError("the parent of the root should only have root as child")
            rootparent = p
            rootid = children[0]

    if rootparent is not None:
        # this is only the case if we have an entry in the child_dict that is not
        # part of all_files, and thus probably part of an imported fileset.
        if None in child_dict:
            raise ValueError("inconsistency: there should be only 1 potential root")

        child_dict.pop(rootparent)
        child_dict[None] = [rootid]

    return directories, child_dict, all_ids


def _determine_rootdir(directories, child_dict):
    ''' return the root directory and unrooted dirs in given hierarchy '''

    rootdir_id = None
    rootdir_path = None

    # Check if this sequence of files contains the path separator as root dir
    if _os.path.sep in directories:
        # in this case, the set of files probably originates from some filesystem parsing
        # tool (i.e. TSK), and they all have some leading path separator. So we expect no
        # files without any path separator, so we will not have '' as parent
        if '' in child_dict:
            raise ValueError("encountered {:} *and* files without path separator".format(_os.path.sep))
        # in this case, we expect a single entry in the child_dict where the parent is None
        if None not in child_dict:
            raise ValueError("no entry in child_dict for {:}".format(_os.path.sep))
        if len(child_dict[None]) != 1:
            raise ValueError("only a single None entry expected in child_dict")
        # consider this to be the root of the tree
        rootdir_id =child_dict[None][0]
        rootdir_path = _os.path.sep

    # now iterate over all directories to determine if there are any
    # directories without a parent directory
    unrooted_dirs = set()
    for mydirname in directories:
        if mydirname == _os.path.sep:
            # this is dealt with separately above
            continue
        else:
            # No need to strip trailing path separator, this is already done by caller
            parentdirname = _os.path.dirname(mydirname)
            if parentdirname not in directories:
                # the parentdir does not exist, which means that this dir has no parent
                unrooted_dirs.add(mydirname)

    if rootdir_id is not None and len(unrooted_dirs) != 0:
        # now, if we have determined the rootdir, we should have no unrooted dirs
        raise ValueError("rootdir detected, but also found unrooted_dirs")

    if rootdir_id is not None:
        # rootdir was already established, which means that the directory
        # with path separator as path is present. Check if all directories
        # in the child_dict start with this path separator.
        # start with the rootdir_path
        for p in child_dict.keys():
            if p is None:
                # skip, this is the one entry for the root dir
                continue
            if not p.startswith(rootdir_path):
                raise ValueError("not all encountered paths start with rootdir_path")
        return rootdir_id, rootdir_path

    # if we get here: rootdir_id is None

    if len(unrooted_dirs) == 1:
        valid_root = True
        # if there is only a single unrooted dir, this might be the actual rootdir,
        # but only if all directories in the child_dict start with this path
        potential_rootdir_path = unrooted_dirs.pop()
        for p in child_dict.keys():
            if p is None:
                # skip, this is the one entry for the root dir
                continue
            if not p.startswith(potential_rootdir_path):
                valid_root = False

        if valid_root is True:
            rootdir_path = potential_rootdir_path
            rootdir_id = directories[rootdir_path]

    return rootdir_id, rootdir_path
