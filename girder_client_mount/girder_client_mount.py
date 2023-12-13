#!/usr/bin/env python3
import argparse
import errno
import functools
import hashlib
import logging
import os
import pathlib
import stat
import sys
import threading
import time

import cachetools
import dateutil.parser
import fuse
import girder_client
import girder_client.cli
import httpio
import requests
from pkg_resources import DistributionNotFound, get_distribution

try:
    __version__ = get_distribution(__name__.split('.')[0]).version
except DistributionNotFound:
    # package is not installed
    __version__ = 'local'

logger = logging.getLogger(__name__)

# See http://docs.python.org/3.3/howto/logging.html#configuring-logging-for-a-library
logging.getLogger(__name__).addHandler(logging.NullHandler())


class ClientFuse(fuse.Operations):
    """
    Handle FUSE operations that are non-default.

    It exposes the Girder resources via the resource path in a read-only
    manner.
    """

    use_ns = True

    def __init__(self, stat=None, gc=None, flatten=None, options=None):
        """
        Instantiate the operations class.

        This sets up tracking for open files and file descriptor numbers
        (handles).

        :param stat: the results of an os.stat call which should be used as
            default values for files in the FUSE.  Files in the FUSE will have
            the same uid, gid, and atime.  If the resource lacks both an
            updated and a created time stamp, the ctime and mtime will also be
            taken from this.  If None, this defaults to the user directory.
        :param gc: a connected girder client.
        :param flatten: if True, make single-file items appear as a file rather
            than a folder containing one file.
        :param options: a dictionary of additional options.  May be modified if
            some options are directly handled rather than are to be passed to
            the mount command.
        """
        super().__init__()
        if not stat:
            stat = os.stat(os.path.expanduser('~'))
        # we always set st_mode, st_size, st_ino, st_nlink, so we don't need
        # to track those.
        self._defaultStat = {key: getattr(stat, key) for key in {
            'st_gid', 'st_uid', 'st_blksize'} if hasattr(stat, key)}
        self._blockSize = self._defaultStat.get('st_blksize')
        if sys.platform.startswith('linux'):
            self._blockSize = 512
        for key in {'st_atime', 'st_ctime', 'st_mtime'}:
            self._defaultStat[key] = int(getattr(stat, key, 0) * 1e9)
        self.gc = gc
        self.flatten = flatten
        self.nextFH = 1
        self.openFiles = {}
        self.openFilesLock = threading.Lock()
        options = options or {}
        self._allow_other = 'allow_other' in options
        self.cache = cachetools.TTLCache(maxsize=10000, ttl=int(options.pop('stat_cache_ttl', 1)))
        self.diskcache = None
        self._configure_disk_cache(options)

    def _configure_disk_cache(self, cacheopts):
        """
        Configure the disk cache.

        :param cacheopts: An optional dictionary of options.  Any option that
            starts with 'diskcache' will be passed to diskcache.Cache without
            the 'diskcache' prefix.  'diskcache' by itself is a boolean to
            enable or disable the diskcache.
        """
        use = None
        try:
            import diskcache
        except ImportError:
            use = False

        options = {
            'directory': '~/.cache/girder-client-mount',
            # It would be nicer to use 'least-recently-used', but it is
            # comparatively expensive, as every access requires a database
            # write.  least-recently-stored does not.
            'eviction_policy': 'least-recently-stored',
            # This seems to be necessary to allow concurrent access from
            # multiple mounts
            'sqlite_journal_mode': 'truncate',
        }
        for key in list((cacheopts or {}).keys()):
            if key.startswith('diskcache'):
                value = cacheopts.pop(key)
                key = key[len('diskcache'):].lstrip('_')
                use = True if use is None else use
                if key:
                    options[key] = value
                elif not value:
                    use = False
        if use:
            chunk = int(options.pop('chunk', 128 * 1024))
            self.diskcache = {
                'chunk': chunk,
                'cache': diskcache.Cache(**options)
            }

    def __call__(self, op, path, *args, **kwargs):
        """
        Generically allow logging and error handling for any operation.

        :param op: operation to perform.
        :param path: path within the fuse (e.g., '', '/user', '/user/<name>',
            etc.).
        """
        logger.debug('-> %s %s %s', op, path, repr(args))
        ret = '[exception]'
        try:
            ret = getattr(self, op)(path, *args, **kwargs)
            return ret
        except Exception as e:
            # Log all exceptions and then reraise them
            if getattr(e, 'errno', None) in (errno.ENOENT, errno.EACCES):
                logger.debug('-- %s %r', op, e)
            else:
                logger.exception('-- %s', op)
            raise e
        finally:
            if op != 'read':
                logger.debug('<- %s %s', op, repr(ret))
            else:
                logger.debug('<- %s (length %d) %r', op, len(ret), ret[:16])

    @cachetools.cachedmethod(lambda self: self.cache, key=functools.partial(
        cachetools.keys.hashkey, '_get_path'))
    def _get_path(self, path):
        """
        Given a fuse path, return the associated resource.

        :param path: path within the fuse.
        :returns: a Girder resource dictionary.
        """
        if path.endswith('/*'):
            path = path[:-1]
        # If asked about a file in top level directory or the top directory,
        # return that it doesn't exist.  Other methods should handle '',
        # 'user', and 'collection' before calling this method.
        if '/' not in path.rstrip('/')[1:]:
            raise fuse.FuseOSError(errno.ENOENT)
        try:
            doc = self.gc.get('resource/lookup', parameters={'path': path.rstrip('/')})
            resource = {'document': doc, 'model': doc['_modelType']}
        except Exception:
            logger.exception('ServerFuse server internal error')
            raise fuse.FuseOSError(errno.ENOENT)
        return resource   # {model, document}

    def _stat(self, doc, model):
        """
        Generate stat results for a resource.

        :param doc: the girder resource document.
        :param model: the girder model.
        :returns: the stat dictionary.
        """
        attr = self._defaultStat.copy()
        # We could specify distinct ino.  For instance, we could generate them
        # via a hash of the document ID (something like  int(hashlib.sha512(
        # str(doc['_id'])).hexdigest()[-8:], 16) ).  There doesn't seem to be
        # any measurable benefit of this, however, so we specify use_ino false
        # in the mount and set the value to -1 here.
        # attr['st_ino'] = -1
        attr['st_ino'] = int(hashlib.sha512(str(doc['_id']).encode()).hexdigest()[-8:], 16)

        attr['st_nlink'] = 1
        if 'updated' in doc:
            attr['st_mtime'] = int(time.mktime(dateutil.parser.parse(
                doc['updated']).timetuple()) * 1e9)
        elif 'created' in doc:
            attr['st_mtime'] = int(time.mktime(dateutil.parser.parse(
                doc['created']).timetuple()) * 1e9)
        attr['st_ctime'] = attr['st_mtime']

        if model == 'item' and self.flatten:
            files = list(self.gc.listFile(doc['_id'], limit=2))
            if len(files) == 1 and files[0]['name'] == doc['name']:
                doc, model = files[0], 'file'
        if model == 'file':
            attr['st_mode'] = (0o444 if self._allow_other else 0o400) | stat.S_IFREG
            attr['st_size'] = doc.get('size', 0)
            if 'size' not in doc and 'linkUrl' in doc:
                with httpio.open(doc['linkUrl']) as f:
                    f.seek(0, os.SEEK_END)
                    attr['st_size'] = f.tell()
        else:
            attr['st_mode'] = (0o555 if self._allow_other else 0o500) | stat.S_IFDIR
            # Directories have zero size.  We could, instead, list the size
            # of all of their children via doc.get('size', 0), but that isn't
            # how most directories are reported.
            attr['st_size'] = 0
        return attr

    def _name(self, doc, model):
        """
        Return the name associated with a Girder resource.

        :param doc: the girder resource document.
        :param model: the girder model.
        :returns: the resource name as a text string.
        """
        name = doc['login' if model == 'user' else 'name']
        if isinstance(name, bytes):
            name = name.decode('utf8')
        return name

    def _list(self, doc, model):
        """
        List the entries in a Girder user, collection, folder, or item.

        :param doc: the girder resource document.
        :param model: the girder model.
        :returns: a list of the names of resources within the specified
        document.
        """
        entries = []
        if model in ('collection', 'user', 'folder'):
            logger.debug('listFolder %r', doc['_id'])
            for folder in self.gc.listFolder(doc['_id'], parentFolderType=model):
                entries.append(self._name(folder, 'folder'))
        if model == 'folder':
            logger.debug('listItem %r', doc['_id'])
            for item in self.gc.listItem(doc['_id']):
                entries.append(self._name(item, 'item'))
        elif model == 'item':
            logger.debug('listFile %r', doc['_id'])
            for file in self.gc.listFile(doc['_id']):
                entries.append(self._name(file, 'file'))
        # we can't reach items with slashes in their names, so don't list them
        entries = [entry for entry in entries if '/' not in entry]
        return entries

    # We don't handle extended attributes or ioctl.
    getxattr = None
    listxattr = None
    ioctl = None

    def access(self, path, mode):
        """
        Try to load the resource associated with a path.

        If we have permission to do so based on the current mode, report that
        access is allowed.  Otherwise, an exception is raised.

        :param path: path within the fuse.
        :param mode: either F_OK to test if the resource exists, or a bitfield
            of R_OK, W_OK, and X_OK to test if read, write, and execute
            permissions are allowed.
        :returns: 0 if access is allowed.  An exception is raised if it is
            not.
        """
        if path.rstrip('/') in ('', '/user', '/collection'):
            return super().access(path, mode)
        # mode is either F_OK or a bitfield of R_OK, W_OK, X_OK
        return 0

    def create(self, path, mode):
        """
        In a read-only system, don't allow create.
        """
        raise fuse.FuseOSError(errno.EROFS)

    def flush(self, path, fh=None):
        """
        Flush writes.

        We may want to disallow flush, since this is a read-only system:
            raise fuse.FuseOSError(errno.EACCES)
        For now, always succeed.
        """
        return 0

    @cachetools.cachedmethod(lambda self: self.cache, key=functools.partial(
        cachetools.keys.hashkey, 'getattr'))
    def getattr(self, path, fh=None):
        """
        Get the attributes dictionary of a path.

        :param path: path within the fuse.
        :param fh: an open file handle.  Ignored, since path is always
            specified.
        :returns: an attribute dictionary.
        """
        if path.rstrip('/') in ('', '/user', '/collection'):
            attr = self._defaultStat.copy()
            attr['st_mode'] = (0o555 if self._allow_other else 0o500) | stat.S_IFDIR
            attr['st_size'] = 0
        else:
            resource = self._get_path(path)
            attr = self._stat(resource['document'], resource['model'])
        if self._blockSize and attr.get('st_size'):
            attr['st_blocks'] = int(
                (attr['st_size'] + self._blockSize - 1) / self._blockSize)
        return attr

    def read(self, path, size, offset, fh):
        """
        Read a block of bytes from a resource.

        :param path: path within the fuse.  Ignored, since the fh parameter
            must be valid.
        :param size: maximum number of bytes to read.  There may be less if
            this is near the end of the file.
        :param offset: the offset within the file to read.
        :param fh: an open file handle.
        :returns: a block of up to <size> bytes.
        """
        with self.openFilesLock:
            if fh not in self.openFiles:
                raise fuse.FuseOSError(errno.EBADF)
            info = self.openFiles[fh]
        if self.diskcache:
            result = b''
            for idx in range(
                    offset // self.diskcache['chunk'],
                    (offset + size + self.diskcache['chunk'] - 1) // self.diskcache['chunk']):
                idxoffset = idx * self.diskcache['chunk']
                idxlen = min(self.diskcache['chunk'], info['size'] - idxoffset)
                key = '%s-%d-%d' % (info['hash'], idxoffset, idxlen)
                try:
                    data = self.diskcache['cache'].get(key, None, read=True)
                except Exception:
                    logger.exception('diskcache threw an exception in get')
                    data = None
                if data is None:
                    with info['lock']:
                        if 'handle' not in info:
                            info['handle'] = httpio.open(info['url'], allow_redirects=True)
                        handle = info['handle']
                        handle.seek(idxoffset)
                        data = handle.read(idxlen)
                    try:
                        self.diskcache['cache'][key] = data
                    except Exception:
                        logger.exception('diskcache threw an exception in set')
                    result += data[max(0, offset - idxoffset):
                                   min(len(data), offset + size - idxoffset)]
                else:
                    data.seek(max(0, offset - idxoffset))
                    result += data.read(size - len(result))
            return result
        with info['lock']:
            if 'handle' not in info:
                info['handle'] = httpio.open(info['url'], allow_redirects=True)
            handle = info['handle']
            handle.seek(offset)
            return handle.read(size)

    def readdir(self, path, fh):
        """
        Get a list of names within a directory.

        :param path: path within the fuse.
        :param fh: an open file handle.  Ignored, since path is always
            specified.
        :returns: a list of names.  This always includes . and ..
        """
        path = path.rstrip('/')
        result = ['.', '..']
        if path == '':
            result.extend(['collection', 'user'])
        elif path in ('/user', '/collection'):
            try:
                if path == '/user':
                    logger.debug('listUser')
                    for doc in self.gc.listUser():
                        result.append(self._name(doc, 'user'))
                else:
                    logger.debug('listCollection')
                    for doc in self.gc.listCollection():
                        result.append(self._name(doc, 'collection'))
            except Exception:
                pass
        else:
            resource = self._get_path(path)
            result.extend(self._list(resource['document'], resource['model']))
        return result

    def open(self, path, flags):
        """
        Open a path and return a descriptor.

        :param path: path within the fuse.
        :param flags: a combination of O_* flags.  This will fail if it is not
            read only.
        :returns: a file descriptor.
        """
        resource = self._get_path(path)
        if resource['model'] == 'item' and self.flatten:
            files = list(self.gc.listFile(resource['document']['_id'], limit=2))
            if len(files) == 1 and files[0]['name'] == resource['document']['name']:
                resource = {'document': files[0], 'model': files[0]['_modelType']}
        if resource['model'] != 'file':
            return super().open(path, flags)
        if flags & (os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_RDWR |
                    os.O_TRUNC | os.O_WRONLY | getattr(os, 'O_ASYNC', 0) |
                    getattr(os, 'O_DIRECTORY', 0)):
            raise fuse.FuseOSError(errno.EROFS)
        info = {
            'path': path,
            'url': self.gc.urlBase + 'file/%s/download?token=%s' % (
                resource['document']['_id'], self.gc.token),
            'hash': (
                resource['document']['sha512']
                if 'sha512' in resource['document'] else
                '%s-%d-%s' % (
                    resource['document']['_id'], resource['document'].get('size', 0),
                    resource['document'].get('updated', resource['document']['created']))),
            'size': resource['document'].get('size', 0),
            'lock': threading.Lock(),
        }
        if resource['document'].get('linkUrl'):
            info['url'] = resource['document']['linkUrl']
        if 'size' not in resource['document']:
            with httpio.open(info['url']) as f:
                f.seek(0, os.SEEK_END)
                info['size'] = f.tell()
        with self.openFilesLock:
            fh = self.nextFH
            self.nextFH += 1
            self.openFiles[fh] = info
        return fh

    def release(self, path, fh):
        """
        Release an open file handle.

        :param path: path within the fuse.
        :param fh: an open file handle.
        :returns: a file descriptor.
        """
        with self.openFilesLock:
            if fh in self.openFiles:
                with self.openFiles[fh]['lock']:
                    if 'handle' in self.openFiles[fh]:
                        self.openFiles[fh]['handle'].close()
                        del self.openFiles[fh]['handle']
                    del self.openFiles[fh]
            else:
                return super().release(path, fh)
        return 0

    def destroy(self, path):
        """
        Handle shutdown of the FUSE.

        :param path: always '/'.
        """
        return super().destroy(path)


class FUSELogError(fuse.FUSE):
    def __init__(self, operations, mountpoint, *args, **kwargs):
        """
        Wrap fuse.FUSE so that errors are logged.

        Don't raise a RuntimeError exception.
        """
        try:
            logger.debug('Mounting %s\n' % mountpoint)
            super().__init__(operations, mountpoint, *args, **kwargs)
            logger.debug('Mounted %s\n' % mountpoint)
        except RuntimeError:
            logger.error(
                'Failed to mount FUSE.  Does the mountpoint (%r) exist and is '
                'it empty?  Does the user have permission to create FUSE '
                'mounts?  It could be another FUSE mount issue, too.' % (
                    mountpoint, ))


def unmount_client(path, lazy=False, quiet=False):
    """
    Unmount a specified path, if possible.

    :param path: the path to unmount.
    :param lazy: True to pass the lazy flag to the unmount command.
    :returns: the return code of the unmount program (0 for success).  A
        non-zero code could mean that the unmount failed or was not needed.
    """
    # We only import these for the unmount command
    import shutil
    import subprocess

    if shutil.which('fusermount'):
        cmd = ['fusermount', '-u']
        if lazy:
            cmd.append('-z')
    else:
        cmd = ['umount']
        if lazy:
            cmd.append('-l')
    cmd.append(os.path.realpath(path))
    if quiet:
        with open(getattr(os, 'devnull', '/dev/null'), 'w') as devnull:
            result = subprocess.call(cmd, stdout=devnull, stderr=devnull)
    else:
        result = subprocess.call(cmd)
    return result


def mount_client(path, gc, fuse_options=None, flatten=False):
    """
    Perform the mount.

    :param path: the mount location.
    :param gc: a connected girder client.
    :param fuse_options: a comma-separated string of options to pass to the
        FUSE mount.  A key without a value is taken as True.  Boolean values
        are case insensitive.  For instance, 'foreground' or 'foreground=True'
        will keep this program running until the SIGTERM or unmounted.
    :param flatten: if True, make single-file items appear as a file rather
        than a folder containing one file.
    """
    path = str(path)
    options = {
        # By default, we run in the background so the mount command returns
        # immediately.  If we run in the foreground, a SIGTERM will shut it
        # down.  On Windows, default to running in the foreground.
        'foreground': sys.platform.startswith('win'),
        # Cache files if their size and timestamp haven't changed.
        # This lets the OS buffer files efficiently.
        'auto_cache': True,
        # We aren't specifying our own inos
        # 'use_ino': False,
        # read-only file system
        'ro': True,
    }
    if sys.platform != 'darwin':
        # Automatically unmount when we try to mount again
        options['auto_unmount'] = True
    if fuse_options:
        for opt in fuse_options.split(','):
            if '=' in opt:
                key, value = opt.split('=', 1)
                value = (False if value.lower() == 'false' else
                         True if value.lower() == 'true' else value)
            else:
                key, value = opt, True
            if key in ('ro', 'rw') and options.get(key) != value:
                logger.warning('Ignoring the %s=%r option' % (key, value))
                continue
            options[key] = value
    flatten = options.pop('flatten', flatten)
    op_class = ClientFuse(stat=os.stat(path), gc=gc, flatten=flatten, options=options)
    FUSELogError(op_class, path, **options)


class GirderClient(girder_client.cli.GirderCli):
    def __init__(self, *args, **kwargs):
        """
        See girder_client.cli.

        This does the same, except maintains a single requests session for the
        whole duration.
        """
        super().__init__(*args, **kwargs)
        self._session = requests.Session()
        self._session.verify = self.sslVerify

    def sendRestRequest(self, *args, **kwargs):  # noqa: N802
        return girder_client.GirderClient.sendRestRequest(self, *args, **kwargs)


def get_girder_client(opts):
    """
    Log in to Girder and return a reference to the client.

    :param opts: options that include the username, password, and girder api
        url.
    :returns: the girder client.
    """
    gcopts = {k: v for k, v in opts.items() if k in {
        'host', 'port', 'apiRoot', 'scheme', 'apiUrl',
        'username', 'password', 'apiKey', 'sslVerify'}}
    gcopts['username'] = gcopts.get('username') or None
    gcopts['password'] = gcopts.get('password') or None
    girder_client.DEFAULT_PAGE_LIMIT = max(girder_client.DEFAULT_PAGE_LIMIT, 250)
    client = GirderClient(**gcopts)
    if opts.get('token'):
        client.setToken(opts['token'])
    return client


def main(args=None):
    parser = argparse.ArgumentParser(
        description='Mount Girder resources as a user file system.  This '
        'requires the fuse library to be installed.  If needed, set the '
        'FUSE_LIBRARY_PATH environment variable to point to libfuse or a '
        'compatible library.')
    # Standard girder_client CLI options
    parser.add_argument(
        '--apiurl', '--api-url', '--api', '--url', '-a', dest='apiUrl',
        help='The Girder api url (e.g., http://127.0.0.1:8080/api/v1).  If '
        'specified, the scheme, host, port, and apiRoot are ignored.')
    parser.add_argument(
        '--apikey', '--api-key', '--key', dest='apiKey',
        default=os.environ.get('GIRDER_API_KEY', None),
        help='An API key, defaults to GIRDER_API_KEY environment variable.')
    parser.add_argument(
        '--username', '--user',
        help='The Girder username.  If not specified, a prompt is given.')
    parser.add_argument(
        '--password', '--pass', '--passwd', '--pw',
        help='The Girder password.  If not specified, a prompt is given.')
    parser.add_argument(
        '--token',
        help='A Girder token to use instead of a username and password.')
    parser.add_argument(
        '--host', help='The Girder API host.  Default is localhost.')
    parser.add_argument(
        '--scheme', help='The Girder API scheme.  Default is http.')
    parser.add_argument(
        '--port', type=int, help='The Girder API port.  If the host is '
        '"localhost", the default is 8080.  Otherwise, the default is 80 if '
        'the scheme is http or 443 if https.')
    parser.add_argument(
        '--apiroot', '--api-root', '--root', dest='apiRoot',
        help='The Girder API root.  Default is /api/v1.')
    parser.add_argument(
        '--no-ssl-verify', action='store_false', dest='sslVerify',
        help='Disable SSL verification.')
    parser.add_argument(
        '--certificate', dest='sslVerify', help='A path to SSL certificate')
    # Generic verbose option
    parser.add_argument(
        '--verbose', '-v', action='count', default=0,
        help='Increase output.')
    parser.add_argument(
        '--silent', '--quiet', '-q', action='count', default=0,
        help='Decrease output.')
    # This program's options
    parser.add_argument('path', type=pathlib.Path)
    parser.add_argument(
        '--options', '-o', dest='fuseOptions',
        help='Comma separated list of additional FUSE mount options.  ro '
        'cannot be overridden.  Some additional options can be specified: '
        'flatten can be specified here rather than as a separate flag.  '
        'Options beginning with diskcache are used to create a diskcache for '
        'somewhat persistent local data storage.  These are passed to '
        'diskcache.Cache with the "diskcache" prefix removed.  diskcache by '
        'itself will enable the default diskcache.  diskcache_directory and '
        'diskcache_size_limit (in bytes) are the most common.  The directory '
        'defaults to ~/.cache/girder-client-mount.  stat_cache_ttl specifies '
        'how long in seconds attributes are cached for girder documents.  A '
        'longer time reduces network access but could result in stale '
        'permissions or miss updates.')
    parser.add_argument(
        '--unmount', '--umount', '-u', action='store_true', default=False,
        help='Unmount a mounted FUSE filesystem.')
    parser.add_argument(
        '--lazy', '-l', '-z', action='store_true', default=False,
        help='Lazy unmount.')
    parser.add_argument(
        '--flatten', action='store_true', default=False,
        help='Flatten single file items so that the item does not appear as a '
        'directory.')
    parser.add_argument(
        '--foreground', '-f', action='store_true', default=False,
        help='Foreground operation (same as -o foreground).')
    parser.add_argument(
        '--debug', action='store_true', default=False,
        help='Enable debug output (same as -o debug,foreground; implies -f).')
    parser.add_argument(
        '--version', '-V', action='version',
        version='%(prog)s {version}'.format(version=__version__))
    args = parser.parse_args(args)
    logging.basicConfig(
        stream=sys.stderr, level=max(1, logging.WARNING - 10 * (args.verbose - args.silent)))
    logger.debug('Parsed arguments: %r', args)
    if sys.platform.startswith('win'):
        args.path = str(args.path).rstrip(':')
        if len(args.path) != 1:
            raise Exception('%s must be a drive letter' % args.path)
    elif not os.path.isdir(args.path):
        raise Exception('%s must be a directory' % args.path)
    if args.unmount or args.lazy:
        result = unmount_client(args.path, args.lazy)
        sys.exit(result)
    if args.debug:
        if 'debug' not in (args.fuseOptions or '').split(','):
            args.fuseOptions = ((args.fuseOptions + ',') if args.fuseOptions else '') + 'debug'
        args.foreground = True
    if args.foreground and 'foreground' not in (args.fuseOptions or '').split(','):
        args.fuseOptions = ((args.fuseOptions + ',') if args.fuseOptions else '') + 'foreground'
    gc = get_girder_client(vars(args))
    mount_client(path=args.path, gc=gc, fuse_options=args.fuseOptions, flatten=args.flatten)


if __name__ == '__main__':
    main()


# You can add girder_client to the list of known filesystem types in linux.
# Create an executable file at /sbin/mount.girder_client that contains
#   #!/usr/bin/env bash
#   sudo -u <user to mount under> girder_client_mount.py --password= \
#       --username= --host "$@"
# then the command
#   mount -t girder_client <host> <path> -o <options>
# will work, prompting for a username and password.  If you have
# girder_client_mount.py installed in a virtualenv, frequently prepending the
# virtualenv's bin directory to the path is enough to use it, so the
# mount.girder_client file becomes
#   #!/usr/bin/env bash
#   sudo -u <user that runs girder> bash -c 'PATH="<virtualenv path>:$PATH" \
#       ${0} ${1+"$@"}' girder_client_mount.py mount --username= \
#       --password= --host "$@"
# You could store credentials in the mount.girder_client file, too.
