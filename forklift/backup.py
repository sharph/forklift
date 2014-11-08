#!/usr/bin/env python

import os
import os.path
import sys
import datetime
import json

from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify

from time import time
from getpass import getpass

import compression
import crypto
import transports

from flexceptions import *

class Backup:
    '''A Backup object represents a backup or restore job, with a local
    path and an attached transport. A crypto object can also be attached.
    (If none is selected, we default to NullEncryption().'''

    def __init__(self, config = None, status = None):
        if config is None:
            config = {}
        self.config = config
        if 'chunksize' not in config:
            self.config['chunksize'] = 1024 * 1024 * 8 # 8MB
        crypto.init(config)
        compression.init(config)
        self.status = status
        self.blockmap = {}
        self.inittime = int(time())
        self.oldfiles = {}
        self.transport = transports.MetaTransport(config, status)
        self.root = '/'

    def _syspath_to_backup(self, path):
        return os.path.relpath(path, self.root)

    def _backup_to_syspath(self, path):
        return os.path.join(self.root, path)

    def _digest(self, data):
        return crypto.hmac(self.config, data)

    def _enc(self, data):
        encrypted = crypto.encrypt(self.config,
                                   compression.compress(self.config, data))
        if len(data) > 0:
            self.status.verbose(" compression -> %d%%" % 
                                (int(float(len(encrypted)) / float(len(data)) * 100), ))
        return encrypted

    def _dec(self, data):
        return compression.decompress(self.config,
                                      crypto.decrypt(self.config, data))

    def _save_manifest(self, data):
        data = crypto.encrypt_then_mac(self.config,
                   compression.compress(self.config, json.dumps(data)))
        self.transport.write_manifest(data, self.inittime)

    def _load_manifest(self, mid):
        data = self.transport.read_manifest(mid)
        return json.loads(compression.decompress(self.config,
                            crypto.auth_then_decrypt(self.config,data)))

    def _get_chunks(self, f):
        '''Generator that takes a file handle and yields tuples consisting
        of a hash of the encrypted chunk of data as well as the
        encrypted chunk of data itself.'''

        data = f.read(self.config['chunksize'])
        while data != '':
            digest = self._digest(data)
            if not self.transport.chunk_exists(digest):
                encdata = self._enc(data)
            else:
                encdata = None
            yield (digest, encdata)
            data = f.read(self.config['chunksize'])

    def load_config_remote(self, passphrase):
        config = self.transport.read_config()
        config = crypto.decrypt_config(config, passphrase)
        config = json.loads(config)
        self.__init__(config, self.status)

    def save_config_remote(self):
        config = json.dumps(self.config)
        config = crypto.encrypt_config(self.config, config)
        self.transport.write_config(config)

    def _local_config_path(self):
        if 'local_config' in self.config:
            return self.config['local_config']
        return os.path.join(self.config['local_paths'][0],
                            '.forklift_config')

    def load_config_local(self, path = None):
        if path is None:
            path = self._local_config_path()
        f = open(path, 'r')
        config = json.load(f)
        f.close()
        self.__init__(config, self.status)

    def save_config_local(self, path = None):
        if path is None:
            path = self._local_config_path()
        f = open(path, 'w')
        f.write(json.dumps(self.config, indent=2))
        f.close()   

    def set_passphrase(self, passphrase):
        crypto.new_passphrase(self.config, passphrase)

    def fetch_chunk(self, chunkhash, verifyonly = False):
        '''Fetches a chunk of the given hash value. First it looks in
        local storage.'''
        if chunkhash in self.blockmap:
            for pos, path in self.blockmap[chunkhash]:
                for pathtotry in [path, path + '.' + str(self.inittime)]:
                    try:
                        f = open(self._backup_to_syspath(pathtotry), 'r')
                        f.seek(pos)
                        data = f.read(self.config['chunksize'])
                        if self._digest(data) == chunkhash:
                            f.close()
                            return data
                    except IOError:
                        pass

        if verifyonly:
            return None

        data = self.transport.read_chunk(chunkhash)
        self.status.update()
        data = self._dec(data)
        if self._digest(data) != chunkhash:
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

        path = self._backup_to_syspath(file_manifest['n'])
        tmppath = path + '.' + str(self.inittime)
        try:
            f = open(tmppath, 'wb')
            bytes_d = self.status.bytes_d
            for chunk in file_manifest['b']:
                f.write(self.fetch_chunk(b64decode(chunk)))
                self.status.chunks_d += 1
                self.status.bytes_d = bytes_d + f.tell()
                self.status.update()
                f.flush()
            self.status.files_d += 1
            self.status.update()
            f.close()
            try:
                os.unlink(path)
            except OSError:
                pass
            os.rename(tmppath, path)
        except BaseException as e:
            self.status.verbose('Cleaning up temporary file!')
            if not f.closed:
                f.close()
            os.unlink(tmppath)
            raise
        os.chmod(path, file_manifest['mode'])
        os.utime(path, (int(file_manifest['mtime']),
                        int(file_manifest['mtime'])))
        self.status.verbose(file_manifest['n'])

    def get_chunklist(self,
                      manifest,
                      return_sizes=False,
                      dupesokay=False):
        '''Fetches a full list of chunk digests from a manifest.'''

        chunklist = []
        chunklist_sizes = []
        if 'files' not in manifest:
            return chunklist
        if dupesokay and not return_sizes:
            chunklist = [b64decode(x) for f in manifest['files']
                            for x in f['b']]
#            chunklist = map(b64decode, sum(map(lambda x: x['b'],
#                                               manifest['files']),
#                                           []))
            return chunklist
        for file_manifest in manifest['files']:
            for count, chunk in enumerate(file_manifest['b']):
                chunk = b64decode(chunk)
                if chunk not in chunklist:
                    chunklist.append(chunk)
                    if (count + 1) * self.config['chunksize'] > \
                            file_manifest['s']:
                        chunklist_sizes.append(file_manifest['s'] %
                                               self.config['chunksize'])
                    else:
                        chunklist_sizes.append(self.config['chunksize'])
        if return_sizes:
            return zip(chunklist, chunklist_sizes)
        return chunklist

    def retention(self, t):
        '''Deletes all manifests older than t. Reads remaining manifests
        and removes unused chunks.'''

        mids = self.transport.list_manifest_ids()
        delete_mids = [mid for mid in mids if mid < t]
        keep_mids = [mid for mid in mids if mid >= t]
        for mid in delete_mids:
            self.transport.del_manifest(mid)
        keep_chunks = set()
        for mid in keep_mids:
            manifest = self._load_manifest(mid)
            keep_chunks.update(self.get_chunklist(manifest,
                                                  dupesokay=True))
        existing_chunks = set(self.transport.list_chunks())
        for chunk in existing_chunks - keep_chunks:
            self.transport.del_chunk(chunk)

    def build_block_map(self, manifest):
        '''Builds a dict (as part of the object) which contains each chunkhash
           and where it can potientially be found in the filesystem.'''

        for f in manifest['files']:
            for pos, chunk in enumerate(f['b']):
                chunk = b64decode(chunk)
                if chunk not in self.blockmap:
                    self.blockmap[chunk] = []
                self.blockmap[chunk].append((pos * self.config['chunksize'],
                                             f['n']))

    def find_needed_chunks(self, chunklist):
        '''Returns a list of chunks not on the local filesystem. Chunklist
           should be a list of tuples with the chunkhash and the chunksize.'''

        needed_chunks = []
        for chunk in chunklist:
            if self.fetch_chunk(chunk[0], verifyonly = True) is None:
                needed_chunks.append(chunk)
        return needed_chunks


    def restore_tree(self, mid = None):
        '''Restores the entire file tree for a given manifest id.'''

        self.status.mode = self.status.RESTORING
        self.status.update()
        if mid is None:
            manifest = self.get_last_manifest()
        else:
            manifest = self._load_manifest(mid)
        self.status.files = len(manifest['files'])
        self.status.bytes = reduce(lambda x,y: x+y['s'],
                                   manifest['files'],
                                   0)
        self.build_block_map(manifest)
        self.transport.prepare_for_restore(
            self.find_needed_chunks(self.get_chunklist(manifest,
                                                       return_sizes = True)))
        for dir_manifest in manifest['dirs']:
            dirname = dir_manifest['n']
            dirpath = self._backup_to_syspath(dirname)
            self.status.dirs += 1
            self.status.update()
            self.status.verbose(dirname)
            try:
                os.makedirs(dirpath)
            except os.error:
                pass
        for file_manifest in manifest['files']:
            self.restore_file(file_manifest)
        for dir_manifest in reversed(manifest['dirs']): #permissions
            dirname = dir_manifest['n']
            dirpath = self._backup_to_syspath(dirname)
            os.chmod(dirpath, dir_manifest['mode'])
            os.utime(dirpath, (int(dir_manifest['mtime']),
                               int(dir_manifest['mtime'])))

        self.status.complete_operation()

    def snap_file(self, full_path, rel_path):
        '''Uploads a file and returns a file manifest. Does not
        re-upload chunks when chunks exist at destination.'''

        self.status.filename(rel_path)
        s = os.stat(full_path)
        file_manifest = {'n': rel_path,
                         'uid': s.st_uid,
                         'gid': s.st_gid,
                         'mode': s.st_mode,
                         'mtime': int(s.st_mtime),
                         'b': []}
        if rel_path in self.oldfiles and \
               file_manifest['mtime'] == self.oldfiles[rel_path]['mtime'] and \
               'd' not in self.oldfiles[rel_path]:  # 'd' is dirty
            file_manifest['b'] = self.oldfiles[rel_path]['b']
            file_manifest['s'] = self.oldfiles[rel_path]['s']
            self.status.chunks += len(file_manifest['b'])
            self.status.files += 1
            self.status.bytes += file_manifest['s']
            self.status.update()
            self.status.filename(None)
            return file_manifest

        f = open(full_path,'rb')
        for chunkhash, chunkdata in self._get_chunks(f):
            if chunkdata is not None:
                try:
                    self.transport.write_chunk(chunkhash, chunkdata)
                except transports.NotRedundant:  # chunk written to >= 1 dest
                    file_manifest['d'] = 1  # mark file dirty
            file_manifest['b'].append(b64encode(chunkhash))
            self.status.chunks += 1
            self.status.update()
        file_manifest['s'] = f.tell()
        self.status.bytes += f.tell()
        f.close()
        self.status.files += 1
        self.status.update()
        self.status.filename(None)
        return file_manifest

    def snap_tree(self):
        '''Uploads a full backup of tree to destination.'''
        self.status.mode = self.status.BACKING_UP
        self.get_last_manifest()
        manifest = {'version': 1,
                    'dirs': [],
                    'files': []}
        self.m = manifest
        for path in self.config['local_paths']:
            path = self._backup_to_syspath(path)
            for root, dirs, files in os.walk(path):
                s = os.stat(root)
                dir_manifest = {'n': self._syspath_to_backup(root),
                                'uid': s.st_uid,
                                'gid': s.st_gid,
                                'mode': s.st_mode,
                                'mtime': int(s.st_mtime)}
                manifest['dirs'].append(dir_manifest)
                self.status.verbose(root)
                for filename in files:
                    full_path = os.path.join(root, filename)
                    backup_path = self._syspath_to_backup(full_path)
                    manifest['files'].append(self.snap_file(full_path,
                                                            backup_path))
                    self.status.verbose(full_path)

        try:
            self._save_manifest(manifest)
        except transports.NotRedundant:
            pass
        self.status.complete_operation()

    def get_last_manifest(self):
        '''Retrieves last manifest from destination for file comparison.'''

        if self.oldfiles != {}:
            return
        mids = self.transport.list_manifest_ids()
        if len(mids) > 0:
            manifest = self._load_manifest(mids[-1])
            self.oldfiles = dict(map(lambda x: (x['n'], x),
                                     manifest['files']))
            return manifest

