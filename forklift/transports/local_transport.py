
import os
import os.path
from binascii import hexlify, unhexlify

from transport import Fail, Transport


class LocalTransport(Transport):

    def __init__(self, path, status):
        self.path = os.path.abspath(path)
        self.tmpblock = os.path.join(self.path, 'temp')
        try:
            os.mkdir(self.path)
        except OSError:
            pass
        self.status = status

    def get_path(self, chunkhash):
        chunkhash = hexlify(chunkhash)
        chunkdir = os.path.join(self.path, 'data', chunkhash[:3],
                                chunkhash[3:6])
        chunkpath = os.path.join(chunkdir, chunkhash)
        return chunkdir, chunkpath

    def chunk_exists(self, chunkhash):
        return os.path.exists(self.get_path(chunkhash)[1])

    def _write_chunk(self, chunkhash, data):
        chunkdir, chunkpath = self.get_path(chunkhash)
        try:
            os.makedirs(chunkdir)
        except os.error:
            pass
        try:
            f = open(self.tmpblock, 'wb')
            f.write(data)
            self.status.inc_t_chunks_u(f.tell())
            f.close()
            os.rename(self.tmpblock, chunkpath)
        except IOError:
            raise Fail

    def _read_chunk(self, chunkhash):
        chunkdir, chunkpath = self.get_path(chunkhash)
        f = open(chunkpath, 'rb')
        data = f.read()
        self.status.inc_t_chunks_d(f.tell())
        f.close()
        return data

    def del_chunk(self, chunkhash):
        chunkhex = hexlify(chunkhash)
        self.status.verbose('deleting %s' % (chunkhex,))
        path = self.get_path(chunkhash)[1]
        os.remove(path)

    def list_chunks(self):
        chunks = []
        for root, dirs, files in os.walk(self.path):
            for filename in files:
                try:
                    chunks.append(unhexlify(filename))
                except TypeError:
                    pass
        return chunks

    def write_manifest(self, manifest, mid):
        path = os.path.join(self.path, '%s.manifest' % int(mid))
        try:
            f = open(self.tmpblock, 'w')
            f.write(manifest)
            self.status.inc_t_chunks_u(f.tell())
            f.close()
            os.rename(self.tmpblock, path)
        except IOError:
            raise Fail

    def read_manifest(self, mid):
        path = os.path.join(self.path, '%s.manifest' % mid)
        try:
            f = open(path, 'r')
        except IOError:
            raise Fail
        manifest = f.read()
        self.status.inc_t_chunks_d(f.tell())
        f.close()
        return manifest

    def write_config(self, settings):
        path = os.path.join(self.path, 'config')
        f = open(path, 'w')
        f.write(settings)
        f.close()

    def read_config(self):
        path = os.path.join(self.path, 'config')
        f = open(path, 'r')
        settings = f.read()
        f.close()
        return settings

    def del_manifest(self, mid):
        path = os.path.join(self.path, '%s.manifest' % mid)
        os.remove(path)

    def list_manifest_ids(self):
        self.status.wait('Listing manifests')
        try:
            listing = os.listdir(self.path)
        except OSError:
            raise Fail
        manifestids = []
        for filename in listing:
            if filename.find('.') == -1:
                continue
            manifestid, fileext = filename.split('.', 2)
            if fileext == 'manifest':
                manifestids.append(int(manifestid))
        self.status.unwait()
        manifestids.sort()
        return manifestids
