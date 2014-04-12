#!/usr/bin/env python

import os
import os.path
import sys

from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify

from time import time
import datetime
from getpass import getpass

import json
import compression
import crypto
import transports
from status import *
from flexceptions import *

class Backup:
    '''A Backup object represents a backup or restore job, with a local
    path and an attached transport. A crypto object can also be attached.
    (If none is selected, we default to NullEncryption().'''
    
    def __init__(self, config, status = None):
        self.config = config
        if 'chunksize' not in config:
            self.config['chunksize'] = 1024 * 1024 * 8 # 8MB
        crypto.init(config)
        compression.init(config)
        self.status = status
        self.blockmap = {}
        self.inittime = int(time())
        self.oldfiles = {}
        self.transport = transports.setup_transport(config, status)

    def digest(self, data):
        return crypto.hmac(self.config, data)
    
    def enc(self, data):
        return crypto.encrypt(self.config,
                              compression.compress(self.config, data))

    def dec(self, data):
        return compression.decompress(self.config,
                                      crypto.decrypt(self.config, data))

    def manifest_enc(self, data):
        pass

    def manifest_dec(self, data):
        return json.loads(compression.decompress(self.config,
                            crypto.auth_then_decrypt(self.config,data)))

    def get_chunks(self, f):
        '''Generator that takes a file handle and yields tuples consisting
        of a hash of the encrypted chunk of data as well as the
        encrypted chunk of data itself.'''

        data = f.read(self.config['chunksize'])
        while data != '':
            digest = self.digest(data)
            if not self.transport.chunk_exists(digest):
                encdata = self.enc(data)
            else:
                encdata = None
            yield (digest, encdata)
            data = f.read(self.config['chunksize'])
        del data
        del encdata
        del digest

    def fetch_chunk(self, chunkhash, verifyonly = False):
        '''Fetches a chunk of the given hash value. First it looks in
        local storage.'''
        if chunkhash in self.blockmap:
            for pos, path in self.blockmap[chunkhash]:
                for pathtotry in [path, path + '.' + str(self.inittime)]:
                    try:
                        f = open(pathtotry, 'r')
                        f.seek(pos)
                        data = f.read(self.config['chunksize'])
                        if self.digest(data) == chunkhash:
                            f.close()
                            return data
                    except IOError:
                        pass

        if verifyonly:
            return None
        
        data = self.transport.read_chunk(chunkhash)
        self.status.update()
        data = self.dec(data)
        if self.digest(data) != chunkhash:
            raise BlockCorruptionError('Block %s corrupted!' %
                                       hexlify(chunkhash))
        return data

    def restore_file(self, file_manifest, dst):
        '''Fetches and restores a file from a given manifest dict.
        
        Manifest format:
        {'n': 'dir/Filename.txt',
         'b': ['123abc...', '234bcd...', 'more base64 encoded digests'],
         's': filesize,
         'mode': os stat mode,
         'mtime': modified time}'''
        
        path = os.path.join(dst, file_manifest['n'])
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
        except Exception as e:
            self.status.verbose('Cleaning up temporary file!')
            f.close()
            os.unlink(tmppath)
            raise
        except KeyboardInterrupt:
            self.status.verbose('Cleaning up temporary file!')
            f.close()
            os.unlink(tmppath)
            raise
        os.chmod(path, file_manifest['mode'])
        os.utime(path, (int(file_manifest['mtime']),
                        int(file_manifest['mtime'])))
        self.status.verbose(file_manifest['n'])

    def get_chunklist(self, manifest, return_sizes = False):
        '''Fetches a full list of chunk digests from a manifest.'''

        chunklist = []
        chunklist_sizes = []
        if 'files' not in manifest:
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
        chunks = []
        for mid in keep_mids:
            manifest = self.transport.read_manifest(mid, self.manifest_dec)
            chunks = chunks + self.get_chunklist(manifest)
        existing_chunks = self.transport.list_chunks()
        keep_chunks = list(set(chunks))
        for chunk in existing_chunks:
            if chunk not in keep_chunks:
                self.transport.del_chunk(chunk)
        
    def build_block_map(self, manifest):
        '''Builds a dict (as part of the object) which contains each chunkhash
           and where it can potientially be found in the filesystem.'''

        for f in manifest['files']:
            for pos, chunk in enumerate(f['b']):
                chunk = b64decode(chunk)
                if chunk not in self.blockmap:
                    self.blockmap[chunk] = []
                p = os.path.join(self.config['local_paths'][0], f['n'])
                self.blockmap[chunk].append((pos * self.config['chunksize'],
                                             p))

    def find_needed_chunks(self, chunklist):
        '''Returns a list of chunks not on the local filesystem. Chunklist
           should be a list of tuples with the chunkhash and the chunksize.'''
        
        needed_chunks = []
        for chunk in chunklist:
            if self.fetch_chunk(chunk[0], verifyonly = True) is None:
                needed_chunks.append(chunk)
        return needed_chunks


    def restore_tree(self, dst, mid = None):
        '''Restores the entire file tree for a given manifest id.'''
    
        self.status.mode = self.status.RESTORING
        self.status.update()
        if mid is None:
            manifest = self.get_last_manifest()
        else:
            manifest = self.transport.read_manifest(mid, dec)
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
            dirpath = os.path.join(dst, dirname)
            self.status.dirs += 1
            self.status.update()
            self.status.verbose(dirname)
            try:
                os.mkdir(dirpath)
            except OSError:
                pass
        for file_manifest in manifest['files']:
            self.restore_file(file_manifest, dst)
        for dir_manifest in reversed(manifest['dirs']): #permissions
            dirname = dir_manifest['n']
            dirpath = os.path.join(self.config['local_paths'][0], dirname)
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
               file_manifest['mtime'] == self.oldfiles[rel_path]['mtime']:
            file_manifest['b'] = self.oldfiles[rel_path]['b']
            file_manifest['s'] = self.oldfiles[rel_path]['s']
            self.status.chunks += len(file_manifest['b'])
            self.status.files += 1
            self.status.bytes += file_manifest['s']
            self.status.update()
            self.status.filename(None)
            return file_manifest

        f = open(full_path,'rb')
        for chunkhash, chunkdata in self.get_chunks(f):
            if chunkdata is not None:
                self.transport.write_chunk(chunkhash, chunkdata)
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
        for root, dirs, files in os.walk(self.config['local_paths'][0]):
            rel_path = os.path.relpath(root, self.config['local_paths'][0])
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
                rel_path = os.path.relpath(full_path,
                                           self.config['local_paths'][0])
                manifest['files'].append(self.snap_file(full_path,
                                                        rel_path))
                self.status.verbose(full_path)

        enc = lambda x: crypto.encrypt_then_mac(self.config,
                            compression.compress(self.config, json.dumps(x)))
        self.transport.write_manifest(manifest, enc)

        self.status.complete_operation()

    def get_last_manifest(self):
        '''Retrieves last manifest from destination for file comparison.'''
        
        if self.oldfiles != {}:
            return
        mids = self.transport.list_manifest_ids()
        if len(mids) > 0:
            manifest = self.transport.read_manifest(mids[-1], self.manifest_dec)
            self.oldfiles = dict(map(lambda x: (x['n'], x),
                                     manifest['files']))
        #else:
        #    self.status.println(
        #        'Could not find any manifest files. Initializing!')
        #    null_manifest = {'version': 1}
        #    self.transport.write_manifest(null_manifest,
        #                                  self.crypto.encrypt_manifest)
        return manifest
 
def main():
    status = ConsoleStatus()
    
    b = Backup(config, status)
#    b.snap_tree()
    status.end()
    exit(0)



if __name__ == '__main__':
    main()
