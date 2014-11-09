
import os
import os.path
from binascii import hexlify

import sqlite3

from transport import Transport, Fail


class SQLiteTransport(Transport):

    def __init__(self, path, status):
        self.path = os.path.abspath(path)
        self.db = lambda: sqlite3.connect(self.path)
        with self.db() as db:
            c = db.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS
                    forklift_store
                (
                    k BLOB PRIMARY KEY,
                    d BLOB
                )
            ''')
            c.execute('''
                CREATE INDEX IF NOT EXISTS k_index
                ON forklift_store (k)
            ''')
            db.commit()
        self.status = status

    def get_k(self, chunkhash):
        return b'c' + chunkhash

    def _store(self, k, d):
        with self.db() as db:
            c = db.cursor()
            c.execute('''
                INSERT INTO forklift_store
                (k, d) VALUES (?, ?)
            ''', (buffer(k), buffer(d)))
        db.commit()

    def _fetch(self, k):
        with self.db() as db:
            c = db.cursor()
            c.execute('''
                SELECT d FROM forklift_store
                WHERE k = ?
            ''', (buffer(k), ))
            res = c.fetchone()
            if res is None:
                raise Fail
            return res[0]

    def _del(self, k):
        with self.db() as db:
            c = db.cursor()
            c.execute('''
                DELETE FROM forklift_store
                where k = ?
            ''', k)
            db.commit()

    def chunk_exists(self, chunkhash):
        with self.db() as db:
            c = db.cursor()
            c.execute('''
                SELECT COUNT(*) FROM forklift_store
                WHERE k = ?
            ''', (buffer(self.get_k(chunkhash)), ))
            return c.fetchone()[0] != 0

    def del_chunk(self, chunkhash):
        chunkhex = hexlify(chunkhash)
        self.status.verbose('deleting %s' % (chunkhex,))
        self._del(self.get_k(chunkhash))

    def _write_chunk(self, chunkhash, data):
        self._store(self.get_k(chunkhash), data)
        self.status.t_bytes_u += len(data)
        self.status.t_chunks_u += 1

    def _read_chunk(self, chunkhash):
        d = self._fetch(self.get_k(chunkhash))
        self.status.t_bytes_d += len(d)
        self.status.t_chunks_d += 1
        return d

    def list_chunks(self):
        with self.db() as db:
            c = db.cursor()
            c.execute('''
                SELECT k FROM forklift_store
                WHERE k like 'c%'
            ''')
            return map(lambda x: x[0][1:], c.fetchall())

    def write_manifest(self, manifest, mid):
        k = 'm.{}'.format(int(mid))
        self._store(k, manifest)
        self.status.t_bytes_u = self.status.t_bytes_u + len(manifest)

    def read_manifest(self, mid):
        k = 'm.{}'.format(int(mid))
        d = self._fetch(k)
        self.status.t_bytes_d = self.status.t_bytes_d + len(d)
        return d

    def write_config(self, settings):
        self._store('s', settings)

    def read_config(self):
        return self._fetch('s')

    def del_manifest(self, mid):
        k = 'm.{}'.format(int(mid))
        self._del(k)

    def list_manifest_ids(self):
        with self.db() as db:
            c = db.cursor()
            self.status.wait('Listing manifests')
            c.execute('''
                SELECT k FROM forklift_store
                WHERE k like 'm.%'
            ''')
            return sorted(map(lambda x: int(x[0][2:]),
                          c.fetchall()))
