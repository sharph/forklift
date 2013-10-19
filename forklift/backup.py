#!/usr/bin/env python

import os
import os.path
import sys

from hashlib import sha256
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify

from argparse import ArgumentParser

from time import time
import datetime
from getpass import getpass

from crypto import *
from transports import *
from status import *
from flexceptions import *

class Backup:
    '''A Backup object represents a backup or restore job, with a local
    path and an attached transport. A crypto object can also be attached.
    (If none is selected, we default to NullEncryption().'''
    
    def __init__(self, path, transport, status = None, crypto = None):
        if crypto is None:
            crypto = NullEncryption()
        self.chunksize = 1024 * 1024 * 8 # 8MB
        self.set_encryption(crypto)
        self.transport = transport
        self.digestsecret = ''
        self.path = os.path.abspath(path)
        self.status = status
        self.blockmap = {}

    def digest(self, data):
        '''Return a binary digest of the digestsecret (to preserve
        confidentiality) and the provided data (usually a chunk.)'''
        return sha256(self.digestsecret + data).digest()

    def set_encryption(self, encryption_module):
        '''Accepts an encryption module and sets the appropriate
        instance variables.'''
        self.crypto = encryption_module
        self.enc = encryption_module.encrypt
        self.dec = encryption_module.decrypt
    
    def get_chunks(self, f):
        '''Generator that takes a file handle and yields tuples consisting
        of a hash of the encrypted chunk of data as well as the
        encrypted chunk of data itself.'''

        data = f.read(self.chunksize)
        while data != '':
            digest = self.digest(data)
            if not self.transport.chunk_exists(digest):
                encdata = self.enc(data)
            else:
                encdata = None
            yield (digest, encdata)
            data = f.read(self.chunksize)
        del data
        del encdata
        del digest

    def fetch_chunk(self, chunkhash):
        '''Fetches a chunk of the given hash value. First it looks in
        local storage.'''
        if chunkhash in self.blockmap:
            for pos, path in self.blockmap[chunkhash]:
                try:
                    f = open(path, 'r')
                    f.seek(pos)
                    data = f.read(self.chunksize)
                    if self.digest(data) == chunkhash:
                        f.close()
                        return data
                except IOError:
                    pass
        
        data = self.transport.read_chunk(chunkhash)
        self.status.update()
        data = self.dec(data)
        if self.digest(data) != chunkhash:
            raise BlockCorruptionError('Block %s corrupted!' %
                                       hexlify(chunkhash))
        return data

    def restore_file(self, file_manifest):
        '''Fetches and restores a file from a given manifest dict.
        
        Manifest format:
        {'n': 'dir/Filename.txt',
         'b': ['123abc...', '234bcd...', 'more base64 encoded digests'],
         's': filesize,
         'mode': os stat mode,
         'mtime': modified time}'''
        
        path = os.path.join(self.path, file_manifest['n'])
        tmppath = path + '-' + str(int(time()))
        f = open(tmppath, 'wb')
        bytes_d = self.status.bytes_d
        for chunk in file_manifest['b']:
            f.write(self.fetch_chunk(b64decode(chunk)))
            self.status.chunks_d = self.status.chunks_d + 1
            self.status.bytes_d = bytes_d + f.tell()
            self.status.update()
        self.status.files_d = self.status.files_d + 1
        self.status.update()
        f.close()
        try:
            os.unlink(path)
        except OSError:
            pass
        os.rename(tmppath, path)
        if 'mode' in file_manifest:
            os.chmod(path, file_manifest['mode'])
        if 'mtime' in file_manifest:
            os.utime(path, (int(file_manifest['mtime']),
                            int(file_manifest['mtime'])))
        self.status.verbose(file_manifest['n'])

    def get_chunklist(self, manifest):
        '''Fetches a full list of needed chunk digests from a manifest.'''

        chunklist = []
        if 'files' not in manifest:
            return chunklist
        for file_manifest in manifest['files']:
            for chunk in file_manifest['b']:
                chunk = b64decode(chunk)
                if chunk not in chunklist:
                    chunklist.append(chunk)
        return chunklist

    def retention(self, t):
        '''Deletes all manifests older than t. Reads remaining manifests
        and removes unused chunks.'''
        
        mids = self.transport.list_manifest_ids()
        delete_mids = [mid for mid in mids if mid < t]
        keep_mids = [mid for mid in mids if mid >= t]
        for mid in delete_mids:
            self.transport.del_manifest(mid)
        chunks = []
        for mid in keep_mids:
            manifest = self.transport.read_manifest(mid,
                            self.crypto.decrypt_manifest)
            chunks = chunks + self.get_chunklist(manifest)
        existing_chunks = self.transport.list_chunks()
        keep_chunks = list(set(chunks))
        for chunk in existing_chunks:
            if chunk not in keep_chunks:
                self.transport.del_chunk(chunk)
        
    def build_block_map(self, manifest):
        for f in manifest['files']:
            for pos, chunk in enumerate(f['b']):
                chunk = b64decode(chunk)
                if chunk not in self.blockmap:
                    self.blockmap[chunk] = []
                p = os.path.join(self.path, f['n'])
                self.blockmap[chunk].append((pos * self.chunksize, p))

    def restore_tree(self, mid = None):
        '''Restores the entire file tree for a given manifest id.'''
    
        self.status.mode = self.status.RESTORING
        self.status.update()
        manifest = self.transport.read_manifest(mid,
                                                self.crypto.decrypt_manifest)
        self.digestsecret = b64decode(manifest['digestsecret'])
        self.chunksize = manifest['chunksize']
        self.status.files = len(manifest['files'])
        self.status.bytes = reduce(lambda x,y: x+y['s'],
                                   manifest['files'],
                                   0)
        self.transport.prepare_for_restore(self.get_chunklist(manifest))
        self.build_block_map(manifest)
        for dir_manifest in manifest['dirs']:
            dirname = dir_manifest['n']
            dirpath = os.path.join(self.path, dirname)
            self.status.dirs = self.status.dirs + 1
            self.status.update()
            self.status.verbose(dirname)
            try:
                os.mkdir(dirpath)
            except OSError:
                pass
        for file_manifest in manifest['files']:
            self.restore_file(file_manifest)
        self.status.println('Done!')

    def snap_file(self, full_path, rel_path):
        '''Uploads a file and returns a file manifest. Does not
        re-upload chunks when chunks exist at destination.'''

        s = os.stat(full_path)
        file_manifest = {'n': rel_path,
                         'uid': s.st_uid,
                         'gid': s.st_gid,
                         'mode': s.st_mode,
                         'mtime': int(s.st_mtime),
                         'b': []}
        f = open(full_path,'rb')
        for chunkhash, chunkdata in self.get_chunks(f):
            if chunkdata is not None:
                self.transport.write_chunk(chunkhash, chunkdata)
            file_manifest['b'].append(b64encode(chunkhash))
            self.status.chunks = self.status.chunks + 1
            self.status.update()
        file_manifest['s'] = f.tell()
        self.status.bytes = self.status.bytes + f.tell()
        f.close()
        self.status.files = self.status.files + 1
        self.status.update()

        return file_manifest
    
    def snap_tree(self):
        '''Uploads a full backup of tree to destination.'''
        self.status.mode = self.status.BACKING_UP
        self.get_digest_secret()
        manifest = {'version': 1,
                    'chunksize': self.chunksize,
                    'dirs': [],
                    'files': [],
                    'digestsecret': b64encode(self.digestsecret)}
        self.m = manifest
        for root, dirs, files in os.walk(self.path):
            rel_path = os.path.relpath(root, self.path)
            s = os.stat(root)
            dir_manifest = {'n': rel_path,
                            'uid': s.st_uid,
                            'gid': s.st_gid,
                            'mode': s.st_mode,
                            'mtime': int(s.st_mtime)}
            manifest['dirs'].append(dir_manifest)
            self.status.verbose(root)
            for filename in files:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, self.path)
                manifest['files'].append(self.snap_file(full_path,
                                                        rel_path))
                self.status.verbose(full_path)

        self.transport.write_manifest(manifest,
                                      self.crypto.encrypt_manifest)

        self.status.println('Backup complete!')

    def get_digest_secret(self):
        '''Retrieves last manifest from destination and uses it to set
        the digest secret. Also, by way of decrypting the manifest, sets
        any salts at the encryption module. Will set a random digest
        secret if no manifests are found.'''

        if self.digestsecret != '':
            return
        mids = self.transport.list_manifest_ids()
        if len(mids) > 0:
            manifest = self.transport.read_manifest(mids[-1],
                                          self.crypto.decrypt_manifest)
            self.digestsecret = b64decode(manifest['digestsecret'])
            try:
                self.chunksize = manifest['chunksize']
            except KeyError:
                self.chunksize = 1024 * 1024 * 16
        else:
            self.status.println(
                'Could not find any manifest files. Initializing!')
            self.digestsecret = os.urandom(16)
            null_manifest = {'version': 1,
                             'digestsecret': b64encode(self.digestsecret),
                             'chunksize': self.chunksize}
            self.transport.write_manifest(null_manifest,
                                          self.crypto.encrypt_manifest)
 
def main():
    status = ConsoleStatus()
    parser = ArgumentParser('a backup application featuring encryption, '
                            'de-duplication, and multiple backends')
    parser.add_argument('path',
                        nargs='?',
                        metavar='PATH',
                        help='the path to backup or restore to')

    parser.add_argument('-b', '--backup',
                        action='store_true',
                        default=False,
                        help='make a backup of the provided path (default)')
    parser.add_argument('-r', '--restore',
                        action='store_true',
                        default=False,
                        help='restore to the provided path')
    parser.add_argument('-l', '--list',
                        action='store_true',
                        default=False,
                        help='display a list of backups on destination')
    parser.add_argument('-t', '--time',
                        type=int,
                        help='restore the backup at the given UNIX timestamp')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        default=False,
                        help='show extra information while running')

    parser.add_argument('--local-backend',
                        action='store',
                        nargs=1,
                        metavar='PATH',
                        help='use a path on the local filesystem as the '
                             'destination')
    parser.add_argument('--s3-backend',
                        action='store',
                        nargs=1,
                        metavar='BUCKETNAME',
                        help='use Amazon S3 as the destination')
    parser.add_argument('--s3-glacier-backend',
                        action='store',
                        nargs=2,
                        metavar=('BUCKETNAME','VAULTNAME'),
                        help='use Amazon Glacer to store the vault data and '
                        'use Amazon S3 to store manifests (vault metadata)')

    parser.add_argument('--encryption',
                        action='store',
                        choices=['aes256','none'],
                        default='aes256',
                        help='choose the type of encryption')

    parser.add_argument('--passphrase',
                        action='store',
                        metavar='PASSPHRASE',
                        help='passphrase to supply to encryption backend '
                             '(warning: insecure!)')

    parser.add_argument('--retention',
                        action='store',
                        nargs=1,
                        metavar='DAYS',
                        help='remove backups and unused chunks older than '
                             'DAYS days (0 will leave most recent backup)')

    (args) = parser.parse_args()
    
    status.printverbose = args.verbose

    if args.local_backend is not None:
        status.verbose('Using local backend.')
        t = LocalTransport(args.local_backend[0], status=status)
    elif args.s3_backend is not None:
        status.verbose('Using S3 backend.')
        t = S3Transport(args.s3_backend[0], status=status)
    elif args.s3_glacier_backend is not None:
        status.verbose('Using S3/Glacier backend.')
        t = S3GlacierTransport(args.s3_glacier_backend[0],
                               args.s3_glacier_backend[1],
                               status=status)
    else:
        status.println('No backend selected!')
        status.end()
        parser.print_help()
        exit(1)

    if args.list == True:
        for mid in t.list_manifest_ids():
            status.println('%s    %d' %
                           (datetime.datetime.fromtimestamp(mid), mid))
        status.end()
        exit(0)

    if args.path is None:
        status.println('PATH not specified.')
        status.end()
        parser.print_help()
        exit(1)

    if args.encryption != 'none':
        if args.passphrase is not None:
            passphrase = args.passphrase
        else:
            print('\r' + (' ' * 78) + '\r')
            passphrase = getpass('Passphrase: ')
        e = AES256Encryption(passphrase)
        del passphrase
    else:
        status.println('Warning: Not using encryption!')
        e = NullEncryption()

    b = Backup(args.path, t, crypto=e, status=status)
    if isinstance(t, S3GlacierTransport):
        b.blocksize = 1024 * 1024 * 16 # 16MB

    mids = t.list_manifest_ids()

    try:
        safe_retention_time = mids[-1] + 1
    except IndexError:
        safe_retention_time = int(time()) - 2

    if args.restore == True:
        if args.time is None:
            active_mid = mids[-1]
        else:
            active_mid = 0
            for mid in mids:
                if mid <= args.time:
                    active_mid = mid
                else:
                    break
        b.restore_tree(active_mid)
    elif args.backup == True:
        
        b.snap_tree()
            
        if args.retention is not None:
            if int(args.retention[0]) < 1:
                b.retention(safe_retention_time)
            else:
                b.retention(time() - (int(args.retention[0])*60*60*24))

    if args.restore == False and args.backup == False:
        status.println('No operation selected!')
        status.end()
        parser.print_help()
        exit(1)


    status.end()
    exit(0)



if __name__ == '__main__':
    main()
