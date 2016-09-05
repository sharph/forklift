
import socket
import json
from time import time, sleep
from binascii import hexlify, unhexlify
from base64 import b64encode

from boto.s3.key import Key
import boto.glacier.exceptions as glacierexceptions
import boto

from transport import Transport, Fail, TryAgain


class S3Transport(Transport):

    def __init__(self, bucket, ia=True, c=None, status=None):
        self.status = status
        self.ia = ia
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
            if self.ia and len(data) > 128 * 1024:
                k.change_storage_class('STANDARD_IA')
        except socket.gaierror:
            raise TryAgain
        self.status.inc_t_chunks_u(len(data))

    def _read_chunk(self, chunkhash):
        chunkhash = hexlify(chunkhash)
        k = Key(self.b)
        k.key = 'data/' + chunkhash
        data = k.get_contents_as_string()
        self.status.inc_t_chunks_d(len(data))
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
        self.status.inc_t_chunks_u(len(data))

    def read_manifest(self, mid):
        k = Key(self.b)
        k.key = 'manifest.%s' % mid
        data = k.get_contents_as_string()
        self.status.inc_t_chunks_d(len(data))
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
        self.status.inc_t_chunks_d(len(data))
        return data

    def write_config(self, config):
        key = 'config'
        k = self.b.new_key(key)
        k.set_contents_from_string(config)
        self.status.inc_t_chunks_u(len(config))


class S3GlacierTransport(S3Transport):

    def __init__(self, bucket, vault=None, c=None, gc=None,
                 status=None, retrieve_bph=1491308088):
        self.ia = False
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
        self.status.inc_t_chunks_u(len(data))

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
        self.status.inc_t_chunks_d(len(data))
        return data
