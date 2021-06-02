#!/usr/bin/env python3
import argparse
import cachetools
import dateutil.parser
import errno
import functools
import fuse
import httpio
import logging
import os
import pathlib
import requests
import stat
import sys
import threading
import time

import girder_client
import girder_client.cli


logger = logging.getLogger(__name__)

# See http://docs.python.org/3.3/howto/logging.html#configuring-logging-for-a-library
logging.getLogger(__name__).addHandler(logging.NullHandler())


class ClientFuse(fuse.Operations):
    """
    This class handles FUSE operations that are non-default.  It exposes the
    Girder resources via the resource path in a read-only manner.
    """

    use_ns = True

    def __init__(self, stat=None, gc=None):
        """
        Instantiate the operations class.  This sets up tracking for open
        files and file descriptor numbers (handles).

        :param stat: the results of an os.stat call which should be used as
            default values for files in the FUSE.  Files in the FUSE will have
            the same uid, gid, and atime.  If the resource lacks both an
            updated and a created time stamp, the ctime and mtime will also be
            taken from this.  If None, this defaults to the user directory.
        :param gc: a connected girder client.
        """
        super().__init__()
        if not stat:
            stat = os.stat(os.path.expanduser('~'))
        # we always set st_mode, st_size, st_ino, st_nlink, so we don't need
        # to track those.
        self._defaultStat = {key: getattr(stat, key) for key in {
            'st_gid', 'st_uid', 'st_blksize'}}
        for key in {'st_atime', 'st_ctime', 'st_mtime'}:
            self._defaultStat[key] = int(getattr(stat, key, 0) * 1e9)
        self.gc = gc
        self.nextFH = 1
        self.openFiles = {}
        self.openFilesLock = threading.Lock()
        self.cache = cachetools.TTLCache(maxsize=10000, ttl=1)

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
        cachetools.keys.hashkey, '_getPath'))
    def _getPath(self, path):
        """
        Given a fuse path, return the associated resource.

        :param path: path within the fuse.
        :returns: a Girder resource dictionary.
        """
        # If asked about a file in top level directory or the top directory,
        # return that it doesn't exist.  Other methods should handle '',
        # '/user', and 'collection' before calling this method.
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
        attr['st_ino'] = -1
        attr['st_nlink'] = 1
        if 'updated' in doc:
            attr['st_mtime'] = int(time.mktime(dateutil.parser.parse(
                doc['updated']).timetuple()) * 1e9)
        elif 'created' in doc:
            attr['st_mtime'] = int(time.mktime(dateutil.parser.parse(
                doc['created']).timetuple()) * 1e9)
        attr['st_ctime'] = attr['st_mtime']

        if model == 'file':
            attr['st_mode'] = 0o400 | stat.S_IFREG
            attr['st_size'] = doc.get('size', len(doc.get('linkUrl', '')))
        else:
            attr['st_mode'] = 0o500 | stat.S_IFDIR
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
        Try to load the resource associated with a path.  If we have permission
        to do so based on the current mode, report that access is allowed.
        Otherwise, an exception is raised.

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
        This is a read-only system, so don't allow create.
        """
        raise fuse.FuseOSError(errno.EROFS)

    def flush(self, path, fh=None):
        """
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
            attr['st_mode'] = 0o500 | stat.S_IFDIR
            attr['st_size'] = 0
        else:
            resource = self._getPath(path)
            attr = self._stat(resource['document'], resource['model'])
        if attr.get('st_blksize') and attr.get('st_size'):
            attr['st_blocks'] = int(
                (attr['st_size'] + attr['st_blksize'] - 1) / attr['st_blksize'])
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
        with info['lock']:
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
            resource = self._getPath(path)
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
        resource = self._getPath(path)
        if resource['model'] != 'file':
            return super().open(path, flags)
        if flags & (os.O_APPEND | os.O_ASYNC | os.O_CREAT | os.O_DIRECTORY |
                    os.O_EXCL | os.O_RDWR | os.O_TRUNC | os.O_WRONLY):
            raise fuse.FuseOSError(errno.EROFS)
        info = {
            'path': path,
            'handle': httpio.open(self.gc.urlBase + 'file/%s/download?token=%s' % (
                resource['document']['_id'], self.gc.token)),
            'lock': threading.Lock(),
        }
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
        This wraps fuse.FUSE so that errors are logged rather than raising a
        RuntimeError exception.
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


def unmountClient(path, lazy=False, quiet=False):
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


def mountClient(path, gc, fuseOptions=None):
    """
    Perform the mount.

    :param path: the mount location.
    :param gc: a connected girder client.
    :param fuseOptions: a comma-separated string of options to pass to the FUSE
        mount.  A key without a value is taken as True.  Boolean values are
        case insensitive.  For instance, 'foreground' or 'foreground=True' will
        keep this program running until the SIGTERM or unmounted.
    """
    path = str(path)
    opClass = ClientFuse(stat=os.stat(path), gc=gc)
    options = {
        # By default, we run in the background so the mount command returns
        # immediately.  If we run in the foreground, a SIGTERM will shut it
        # down
        'foreground': False,
        # Cache files if their size and timestamp haven't changed.
        # This lets the OS buffer files efficiently.
        'auto_cache': True,
        # We aren't specifying our own inos
        'use_ino': False,
        # read-only file system
        'ro': True,
    }
    if sys.platform != 'darwin':
        # Automatically unmount when we try to mount again
        options['auto_unmount'] = True
    if fuseOptions:
        for opt in fuseOptions.split(','):
            if '=' in opt:
                key, value = opt.split('=', 1)
                value = (False if value.lower() == 'false' else
                         True if value.lower() == 'true' else value)
            else:
                key, value = opt, True
            if key in ('use_ino', 'ro', 'rw') and options.get(key) != value:
                logger.warning('Ignoring the %s=%r option' % (key, value))
                continue
            options[key] = value
    FUSELogError(opClass, path, **options)


class GirderClient(girder_client.cli.GirderCli):
    def __init__(self, *args, **kwargs):
        """
        See girder_client.cli.  This does the same, except maintains a single
        requests session for the whole duration.
        """
        super().__init__(*args, **kwargs)
        self._session = requests.Session()
        self._session.verify = self.sslVerify

    def sendRestRequest(self, *args, **kwargs):
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
    return GirderClient(**gcopts)


def main():
    parser = argparse.ArgumentParser(
        description='Generate a bounding polygon for a nitf file.')
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
        help='The Girder admin username.  If not specified, a prompt is given.')
    parser.add_argument(
        '--password', '--pass', '--passwd', '--pw',
        help='The Girder admin password.  If not specified, a prompt is given.')
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
        help='Comma separated list of additional FUSE mount options.  ro and '
        'use_ino cannot be overridden.')
    parser.add_argument(
        '--unmount', '--umount', '-u', action='store_true', default=False,
        help='Unmount a mounted FUSE filesystem.')
    parser.add_argument(
        '--lazy', '-l', '-z', action='store_true', default=False,
        help='Lazy unmount.')
    args = parser.parse_args()
    logging.basicConfig(
        stream=sys.stderr, level=max(1, logging.WARNING - 10 * (args.verbose - args.silent)))
    logger.debug('Parsed arguments: %r', args)
    if not os.path.isdir(args.path):
        raise Exception('%s must be a directory' % args.path)
    if args.unmount or args.lazy:
        result = unmountClient(args.path, args.lazy)
        sys.exit(result)
    gc = get_girder_client(vars(args))
    mountClient(path=args.path, gc=gc, fuseOptions=args.fuseOptions)


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
