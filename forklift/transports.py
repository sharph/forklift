
import os
import os.path
import sys
import socket
import json
from time import time, sleep
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

from httplib import IncompleteRead

from boto.s3.connection import S3Connection
from boto.s3.key import Key
import boto.glacier.exceptions as glacierexceptions
import boto


class Fail(Exception):
    pass


class TryAgain(Exception):
    pass

class NotRedundant(Exception):
    pass


class Transport:
    '''
    Class containing some helper's for child classes. A Transport is an object
    which abstracts remote storage backends.
    '''

    def _backoff(self, op, failexception):
        '''
        Method to implement an exponential backoff algorithm aroud a function.
        Ruturns the value of op() and retries if a TryAgain exception is
        raised. Raises whatever excpetion is passed as failexception if
        maxtries is reached.

        Ideally you would pass this method a lambda for op.
        '''
        backoff = 2
        maxbackoff = 60 * 2
        maxtries = 80
        for tries in xrange(maxtries):
            try:
                return op()
            except TryAgain:
                self.status.wait('err waiting %d seconds' %
                                 (backoff, ))
                sleep(backoff)
                self.status.unwait()
                backoff *= 2
                if backoff > maxbackoff:
                    backoff = maxbackoff
        raise failexception

    def read_chunk(self, chunkhash):
        '''Wrap the private _read_chunk method with a backoff algorithm.'''

        return self._backoff(lambda: self._read_chunk(chunkhash), Fail)

    def write_chunk(self, chunkhash, data):
        '''Wrap the private _write_chunk method with a backoff algorithm.'''

        return self._backoff(lambda: self._write_chunk(chunkhash, data),
                             Fail)

    def prepare_for_restore(self, chunks):
        '''
        Remove any chunks that are stored in this backend from the chunk
        list passed to this method, so that any backends called later
        with this method can prepare appropriately (such as the Glacier
        backend.)
        '''

        for chunk in self.list_chunks():
            for t in chunks:
                if t[0] == chunk:
                    chunks.remove(t)
                    break

    def refresh_cache(self):
        pass


class MetaTransport(Transport):
    '''
    A MetaTransport is an object that sets up and contains real transports.
    It knows how to properly delegate the functionality of a Transport
    object to real transports, while handling redundancy and temporary
    failure.
    '''

    def __init__(self, config, status):
        '''
        Build a list of transport objects from a configuration structure.
        Also, attaches a status object to the transports so that they can
        update the UI.
        '''

        self.status = status
        self.transports = []
        if 'destination' not in config:
            return
        if 'redundancy' in config:
            self.redundancy = config['redundancy']
        else:
            self.redundancy = 3 if len(config['destination']) >= 3 else \
                len(config['destination'])
        for t_config in config['destination']:
            self.transports.append(self._setup_transport(t_config, status))
        self.wtransports = self.transports[:]

    def _setup_transport(self, t_config, status):
        '''Given a config, returns a transport object.'''

        if t_config['type'] == 'local':
            return LocalTransport(t_config['path'], status)

        elif t_config['type'] == 's3':
            s3conn = boto.connect_s3(t_config['aws_access_key_id'],
                                     t_config['aws_secret_access_key'])
            return S3Transport(t_config['bucket'], s3conn, status)

        elif t_config['type'] == 'glacier':
            s3conn = boto.connect_s3(t_config['aws_access_key_id'],
                                     t_config['aws_secret_access_key'])
            glconn = boto.connect_glacier(t_config['aws_access_key_id'],
                                          t_config['aws_secret_access_key'])
            bph = t_config['bph'] if 'bph' in t_config else 1491308088
            vault = t_config['vault'] if 'vault' in t_config else \
                t_config['bucket']
            return S3GlacierTransport(t_config['bucket'],
                                      vault,
                                      s3conn,
                                      glconn,
                                      status,
                                      bph)

    def prepare_for_restore(self, chunks):
        for t in self.transports:
            t.prepare_for_restore(chunks)

    def chunk_exists(self, chunk):
        '''
        Returns True if chunk exists in enough places to satisfy redundancy
        requirements.
        '''

        count = 0
        for t in self.transports:
            if t.chunk_exists(chunk):
                count += 1
                if count >= self.redundancy:
                    return True
        return False

    def write_chunk(self, chunkhash, data):
        '''
        Writes chunk in enough places to satisfy redundancy requirements.
        '''

        wtransports = []
        redundancy = self.redundancy
        for t in self.wtransports:
            if t.chunk_exists(chunkhash):
                redundancy -= 1
            else:
                wtransports.append(t)
        n = 0
        for t in wtransports:
            if n >= redundancy:
                break
            try:
                self._backoff(lambda: t.write_chunk(chunkhash, data), Fail)
                n += 1
            except Fail:
                pass
        self.wtransports.append(self.wtransports.pop(0))
        if n == 0:
            if redundancy < self.redundancy:
                raise NotRedundant
            raise Fail
        if n < redundancy:
            raise NotRedundant

    def _read_chunk(self, chunkhash):
        '''
        Private method to be called by read_chunk in parent class (Transport.)

        If TryAgain is catched, move on to the next transport. If all
        if all transports raise TryAgain, raise it from this function so that
        _backoff can retry all the transports and handle backoff timing
        appropriately.
        '''

        for t in self.transports:
            if t.chunk_exists(chunkhash):
                try:
                    return t._read_chunk(chunkhash)
                except TryAgain:
                    pass
        raise TryAgain

    def del_chunk(self, chunkhash):
        for t in self.transports:
            if t.chunk_exists(chunkhash):
                t.del_chunk(chunkhash)

    def list_chunks(self):
        '''
        Compile a list of all known chunks in all transports.
        '''

        chunks = set()
        for t in self.transports:
            chunks.update(t.list_chunks())
        return chunks

    def write_manifest(self, manifest, mid):
        fails = 0
        for t in self.transports:
            try:
                t.write_manifest(manifest, mid)
            except Fail:
                fails += 1
        if fails > self.redundancy:
            raise Fail
        if fails > 0:
            raise NotRedundant

    def read_manifest(self, mid):
        for t in self.transports:
            try:
                return t.read_manifest(mid)
            except Fail:
                pass
        raise Fail

    def del_manifest(self, mid):
        for t in self.transports:
            t.del_manifest(mid)

    def list_manifest_ids(self):
        mids = []
        for t in self.transports:
            try:
                mids += t.list_manifest_ids()
            except Fail:
                pass
        return sorted(list(set(mids)))

    def write_config(self, config):
        for t in self.transports:
            t.write_config(config)

    def read_config(self, config):
        for t in self.transports:
            try:
                return t.read_config()
            except Fail:
                pass
        raise Fail


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
            self.status.t_bytes_u += f.tell()
            self.status.t_chunks_u += 1
            f.close()
            os.rename(self.tmpblock, chunkpath)
        except IOError:
            raise Fail

    def _read_chunk(self, chunkhash):
        chunkdir, chunkpath = self.get_path(chunkhash)
        f = open(chunkpath, 'rb')
        data = f.read()
        self.status.t_bytes_d += f.tell()
        self.status.t_chunks_d += 1
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
            self.status.t_bytes_u = self.status.t_bytes_u + f.tell()
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
        self.status.t_bytes_d = self.status.t_bytes_d + f.tell()
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


class S3Transport(Transport):

    def __init__(self, bucket, c=None, status=None):
        self.status = status
        if c is None:
            c = boto.connect_s3()
        self.c = c
        try:
            self.b = c.get_bucket(bucket)
        except boto.exception.S3ResponseError:
            self.b = c.create_bucket(bucket)

    def chunk_exists(self, chunkhash):
        chunkhash = hexlify(chunkhash)
        k = Key(self.b)
        k.key = 'data/' + chunkhash
        try:
            return k.exists()
        except socket.gaierror:
            raise TryAgain

    def _write_chunk(self, chunkhash, data):
        chunkhash = hexlify(chunkhash)
        try:
            k = self.b.new_key('data/' + chunkhash)
            k.set_contents_from_string(data)
        except socket.gaierror:
            raise TryAgain
        self.status.t_chunks_u += 1
        self.status.t_bytes_u += len(data)

    def _read_chunk(self, chunkhash):
        chunkhash = hexlify(chunkhash)
        k = Key(self.b)
        k.key = 'data/' + chunkhash
        data = k.get_contents_as_string()
        self.status.t_chunks_d += 1
        self.status.t_bytes_d += len(data)
        return data

    def del_chunk(self, chunkhash):
        chunkhash = hexlify(chunkhash)
        self.status.verbose('deleting %s' % (chunkhash,))
        self.status.wait('Deleting chunk %s...' % (chunkhash[:8], ))
        self.b.delete_key('data/' + chunkhash)
        self.status.unwait()

    def list_chunks(self):
        self.status.wait('Listing chunks...')
        chunks = map(lambda x: unhexlify(x.name[5:]),
                     self.b.list(prefix='data/'))
        self.status.unwait()
        return chunks

    def write_manifest(self, manifest, mid):
        key = 'manifest.%s' % int(mid)
        k = self.b.new_key(key)
        data = manifest
        k.set_contents_from_string(data)
        self.status.t_bytes_u += len(data)

    def read_manifest(self, mid):
        k = Key(self.b)
        k.key = 'manifest.%s' % mid
        data = k.get_contents_as_string()
        self.status.t_bytes_d += len(data)
        return data

    def del_manifest(self, mid):
        self.status.wait('Deleting manifest %d' % (mid, ))
        self.b.delete_key('manifest.%d' % (mid, ))
        self.status.unwait()

    def list_manifest_ids(self):
        self.status.wait('Listing manifests')
        manifestids = []
        for key in self.b.list(prefix='manifest.'):
            filepre, manifestid = key.key.split('.', 2)
            manifestids.append(int(manifestid))
        manifestids.sort()
        self.status.unwait()
        return manifestids

    def read_config(self, config):
        k = Key(self.b)
        k.key = 'config'
        data = k.get_contents_as_string()
        self.status.t_bytes_d += len(data)
        return data

    def write_config(self, config):
        key = 'config'
        k = self.b.new_key(key)
        k.set_contents_from_string(config)
        self.status.t_bytes_u += len(config)


class S3GlacierTransport(S3Transport):

    def __init__(self, bucket, vault=None, c=None, gc=None,
                 status=None, retrieve_bph=1491308088):
        if vault is None:
            vault = bucket
        self.retries = 40
        self.status = status
        if c is None:
            c = boto.connect_s3()
        if gc is None:
            gc = boto.connect_glacier()
        self.bucket = bucket
        self.vault = vault
        self.c = c
        try:
            self.b = c.get_bucket(bucket)
        except boto.exception.S3ResponseError:
            self.b = c.create_bucket(bucket)
        try:
            self.v = gc.get_vault(vault)
        except glacierexceptions.UnexpectedHTTPResponseError:
            self.v = gc.create_vault(vault)
        self.gl1 = self.v.layer1
        self.gc = gc
        self.get_jobs()
        self.chunk_queue = []
        self.aid_cache = {}
        self.last_job_creation = 0
        self.bph = retrieve_bph

    def _get_aid(self, chunkhash):
        if chunkhash not in self.aid_cache:
            self.aid_cache[chunkhash] = S3Transport._read_chunk(self,
                                                                chunkhash)
        return self.aid_cache[chunkhash]

    def _set_aid(self, chunkhash, aid):
        S3Transport._write_chunk(self, chunkhash, aid)
        self.aid_cache[chunkhash] = aid

    def add_more_jobs(self):
        t = time()
        if t - self.last_job_creation < 60 * 60:
            return
        self.last_job_creation = t
        bth = 0
        while self.chunk_queue != [] and bth < self.bph:
            chunk, size = self.chunk_queue.pop(0)
            chunkhex = hexlify(chunk)[:8]
            aid = self._get_aid(chunk)
            if aid not in self.jobs or \
                    self.jobs[aid]['StatusCode'] == 'Failed':
                self.status.wait('Creating job for %s...' % (chunkhex,))
                self.status.verbose('Retrieving %s...' % (chunkhex,))
                self.add_job(aid)
                bth += size
        self.status.unwait()

    def add_job(self, aid):
        job_data = {'ArchiveId': aid,
                    'Description': '',
                    'Type': 'archive-retrieval'}
        job = self.gl1.initiate_job(self.vault, job_data=job_data)
        self.jobs[aid] = self.describe_job(job['JobId'])

    def prepare_for_restore(self, chunks):
        self.chunk_queue = []

        for chunk in self.list_chunks():
            for t in chunks:
                if t[0] == chunk:
                    chunks.remove(t)
                    self.chunk_queue.append(t)
        self.add_more_jobs()

    def wait_on_job(self, job):
        self.add_more_jobs()
        job = self.describe_job(job['JobId'])
        while job['StatusCode'] == 'InProgress':
            self.status.wait('Waiting for glacier job')
            sleep(60 * 5)  # 5 minutes
            self.add_more_jobs()
            job = self.describe_job(job['JobId'])
        if job['StatusCode'] != 'Succeeded':
            raise Exception('Job failed!')
        self.status.unwait()
        return job

    def list_jobs(self):
        self.status.wait('Listing glacier jobs...')
        counter = 1
        job_list = json.loads(self.gl1.list_jobs(self.vault).read())
        jobs = job_list['JobList']
        while 'Marker' in job_list and job_list['Marker'] is not None:
            counter += 1
            self.status.wait('Listing glacier jobs (%d)' % (counter,))
            job_list = json.loads(self.gl1.list_jobs(self.vault,
                                                     marker=job_list['Marker']
                                                     ).read())
            jobs = jobs + job_list['JobList']
        self.status.unwait()
        return jobs

    def describe_job(self, jobid):
        def describe(jobid):
            try:
                return json.loads(self.gl1.describe_job(self.vault,
                                                        jobid).read())
            except socket.gaierror:
                raise TryAgain

        return self._backoff(lambda: describe(jobid), Fail)

    def get_jobs(self):
        self.inv_retrieval_job = None
        self.jobs = {}
        for job in self.list_jobs():
            if job['Action'] == 'InventoryRetrieval':
                self.inv_retrieval_job = job
            else:
                if job['ArchiveId'] not in self.jobs or \
                    job['StatusCode'] == 'Succeeded' or \
                    job['CreationDate'] < \
                        self.jobs[job['ArchiveId']]['CreationDate'] or \
                        self.jobs[job['ArchiveId']]['StatusCode'] == 'Failed':
                    self.jobs[job['ArchiveId']] = job

    def del_chunk(self, chunkhash):
        aid = self._get_aid(chunkhash)
        S3Transport.del_chunk(self, chunkhash)
        del self.aid_cache[chunkhash]
        self.v.delete_archive(aid)

    def _write_chunk(self, chunkhash, data):
        try:
            writer = self.v.create_archive_writer(
                description=b64encode(chunkhash))
            writer.write(data)
            writer.close()
        except glacierexceptions.UnexpectedHTTPResponseError:
            raise TryAgain
        except socket.gaierror:
            raise TryAgain
        self._set_aid(chunkhash, writer.get_archive_id())
        self.status.t_chunks_u += 1
        self.status.t_bytes_u += len(data)

    def _read_chunk(self, chunkhash):
        aid = self._get_aid(chunkhash)
        if aid not in self.jobs or self.jobs[aid]['StatusCode'] == 'Failed':
            self.chunk_queue.insert(0, (chunkhash, 16 * 1024 * 1024))
        ready_job = self.wait_on_job(self.jobs[aid])

        try:
            data = self.gl1.get_job_output(self.vault,
                                           ready_job['JobId']).read()
        except glacierexceptions.UnexpectedHTTPResponseError:
            raise TryAgain
        except socket.gaierror:
            raise TryAgain
        self.status.t_chunks_d += 1
        self.status.t_bytes_d += len(data)
        return data

