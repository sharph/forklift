
import os
import os.path
import sys
import json
from time import time, sleep
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

from httplib import IncompleteRead

from boto.s3.connection import S3Connection
from boto.s3.key import Key
import boto.glacier.exceptions as glacierexceptions
import boto

class LocalTransport:

    def __init__(self, path, status):
        self.path = os.path.abspath(path)
        try:
            os.mkdir(self.path)
        except OSError:
            pass
        self.status = status

    def prepare_for_restore(self, chunks):
        pass

    def get_path(self, chunkhash):
        chunkhash = hexlify(chunkhash)
        chunkdir = os.path.join(self.path, 'data', chunkhash[:2])
        chunkpath = os.path.join(chunkdir, chunkhash)
        return chunkdir, chunkpath

    def chunk_exists(self, chunkhash):
        return os.path.exists(self.get_path(chunkhash)[1])

    def write_chunk(self, chunkhash, data):
        chunkdir, chunkpath = self.get_path(chunkhash)
        try:
            os.makedirs(chunkdir)
        except os.error:
            pass
        f = open(chunkpath, 'wb')
        f.write(data)
        self.status.t_bytes_u += f.tell()
        self.status.t_chunks_u += 1
        f.close()

    def read_chunk(self, chunkhash):
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
    
    def write_manifest(self, manifest, enc):
        path = os.path.join(self.path, '%s.manifest' % int(time()) )
        f = open(path, 'w')
        f.write(enc(json.dumps(manifest)))
        self.status.t_bytes_u = self.status.t_bytes_u + f.tell()
        f.close()

    def read_manifest(self, mid, dec):
        path = os.path.join(self.path, '%s.manifest' % mid )
        f = open(path, 'r')
        manifest = json.loads(dec(f.read()))
        self.status.t_bytes_d = self.status.t_bytes_d + f.tell()
        f.close()
        return manifest

    def del_manifest(self, mid):
        path = os.path.join(self.path, '%s.manifest' % mid )
        os.remove(path)
    
    def list_manifest_ids(self):
        self.status.wait('Listing manifests')
        listing = os.listdir(self.path)
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

    def refresh_cache(self):
        pass

class S3Transport:

    def __init__(self, bucket, c = None, status = None):
        self.status = status
        if c is None:
            c = boto.connect_s3()
        self.c = c
        try:
            self.b = c.get_bucket(bucket)
        except boto.exception.S3ResponseError:
            self.b = c.create_bucket(bucket)

    def prepare_for_restore(self, chunks):
        pass

    def chunk_exists(self, chunkhash):
        chunkhash = hexlify(chunkhash)
        k = Key(self.b)
        k.key = 'data/' + chunkhash
        return k.exists()

    def write_chunk(self, chunkhash, data):
        chunkhash = hexlify(chunkhash)
        k = self.b.new_key('data/' + chunkhash)
        k.set_contents_from_string(data)
        self.status.t_chunks_u += 1
        self.status.t_bytes_u += len(data)

    def read_chunk(self, chunkhash):
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

    def write_manifest(self, manifest, enc):
        key = 'manifest.%s' % int(time())
        k = self.b.new_key(key)
        data = enc(json.dumps(manifest))
        k.set_contents_from_string(data)
        self.status.t_bytes_u += len(data)

    def read_manifest(self, mid, dec):
        k = Key(self.b)
        k.key = 'manifest.%s' % mid
        data = k.get_contents_as_string()
        self.status.t_bytes_d += len(data)
        return json.loads(dec(data))

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

    def refresh_cache(self):
        pass

class S3GlacierTransport:

    def __init__(self, bucket, vault = None, c = None, gc = None,
                 status = None, retrieve_bph = 1491308088):
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
        self.glacier_cache_dir = os.path.join(os.environ['HOME'],
                                              '.forklift')
        self.glacier_cache_file = os.path.join(self.glacier_cache_dir,
                                               vault + '-cache')
        self.glacier_cache = {}
        try:
            os.mkdir(self.glacier_cache_dir)
        except OSError:
            pass
        self.load_archive_ids()
        self.get_jobs()
        self.chunk_queue = []
        self.last_job_creation = 0
        self.bph = retrieve_bph

    def add_more_jobs(self):
        t = time()
        if t - self.last_job_creation < 60 * 60:
            return
        self.last_job_creation = t
        bth = 0
        while self.chunk_queue != [] and bth < self.bph:
            chunk, size = self.chunk_queue.pop(0)
            chunkhex = hexlify(chunk)[:8]
            chunkhash = b64encode(chunk)
            if chunkhash not in self.glacier_cache:
                raise Exception('chunk not in glacier cache')
            aid = self.glacier_cache[chunkhash]
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
        self.chunk_queue = chunks[:]
        self.add_more_jobs()

    def wait_on_job(self, job):
        self.add_more_jobs()
        job = self.describe_job(job['JobId'])
        while job['StatusCode'] == 'InProgress':
            self.status.wait('Waiting for glacier job')
            sleep(60 * 5) # 5 minutes
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
        while True:
            try:
                return json.loads(self.gl1.describe_job(self.vault,
                                                        jobid).read())
            except socket.gaierror:
                sleep(60)
                continue


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

    def refresh_cache(self):
        self.status.wait('Waiting on glacier inventory')
        if self.inv_retrieval_job is None:
            self.inv_retrieval_job = self.retrieve_inventory()
        while self.inv_retrieval_job.status_code == 'InProgress':
            sleep(60 * 10) # 10 minutes
            self.inv_retrieval_job = self.v.get_job(
                                        self.inv_retrieval_job.id)
        if self.inv_retrieval_job.status_code != 'Succeeded':
            raise Exception('Inventory failed!')
        self.glacier_cache = {}
        for archive in self.inv_retrieval_job.get_output()['ArchiveList']:
            self.glacier_cache[archive['ArchiveDescription']] = \
                archive['ArchiveId']
        self.save_archive_ids()
        self.status.unwait()
        
    def load_archive_ids(self):
        try:
            f = open(self.glacier_cache_file, 'r')
            self.glacier_cache = json.load(f)
            f.close()
        except IOError:
            self.save_archive_ids()

    def save_archive_ids(self):
        try:
            f = open(self.glacier_cache_file, 'w')
            f.write(json.dumps(self.glacier_cache))
            f.close()
        except KeyboardInterrupt:
            f.close()
            self.save_archive_ids()
            raise KeyboardInterrupt

    def del_chunk(self, chunkhash):
        chunkhex = hexlify(chunkhash)
        chunkhash = b64encode(chunkhash)
        self.status.verbose('deleting %s' % (chunkhex,))
        aid = self.glacier_cache[chunkhash]
        del self.glacier_cache[chunkhash]
        self.save_archive_ids()
        self.v.delete_archive(aid)

    def list_chunks(self):
        return map(lambda x: b64decode(x), self.glacier_cache.keys())

    def del_manifest(self, mid):
        self.status.wait('Deleting manifest %d' % (mid, ))
        self.b.delete_key('manifest.%d' % (mid, ))
        self.status.unwait()

    def chunk_exists(self, chunkhash):
        chunkhash = b64encode(chunkhash)
        return chunkhash in self.glacier_cache

    def write_chunk(self, chunkhash, data):
        chunkhash = b64encode(chunkhash)
        backoff = 2
        tries = 0
        while True:
            try:
                writer = self.v.create_archive_writer(description=chunkhash)
                writer.write(data)
                writer.close()
                chunkwritten = True
            except glacierexceptions.UnexpectedHTTPResponseError as err:
                tries += 1
                if tries > self.retries:
                    raise ChunkWriteError
                self.status.wait('%s waiting %d seconds' %
                                 (err.message, backoff))
                sleep(backoff)
                self.status.unwait()
                backoff *= 2
                if backoff > 240:
                    backoff = 240
            except socket.gaierror:
                self.status.wait('Network issues... waiting...')
                sleep(60)
                self.status.unwait()
                continue
            break
        self.glacier_cache[chunkhash] = writer.get_archive_id()
        self.save_archive_ids()
        self.status.t_chunks_u += 1
        self.status.t_bytes_u += len(data)

    def read_chunk(self, chunkhash):
        chunkhash = b64encode(chunkhash)
        if chunkhash not in self.glacier_cache:
            raise Exception('chunk not in glacier cache!')
        aid = self.glacier_cache[chunkhash]
        if aid not in self.jobs or self.jobs[aid]['StatusCode'] == 'Failed':
            self.chunk_queue.insert(0, (b64decode(chunkhash), 16 * 1024 * 1024))
        ready_job = self.wait_on_job(self.jobs[aid])

        backoff = 2
        tries = 0
        while True:
            try:
                data = self.gl1.get_job_output(self.vault,
                                               ready_job['JobId']).read()
            except glacierexceptions.UnexpectedHTTPResponseError as err:
                tries += 1
                if tries > self.retries:
                    raise ChunkReadError
                self.status.wait('%s waiting %d seconds' %
                                 (err.message, backoff))
                sleep(backoff)
                self.status.unwait()
                backoff *= 2
                if backoff > 240:
                    backoff = 240
                continue
            except socket.gaierror:
                self.status.wait('Network issues... waiting...')
                sleep(60)
                self.status.unwait()
                continue
            break
        self.status.t_chunks_d += 1
        self.status.t_bytes_d += len(data)
        return data

    def write_manifest(self, manifest, enc):
        key = 'manifest.%s' % int(time())
        k = self.b.new_key(key)
        data = enc(json.dumps(manifest))
        k.set_contents_from_string(data)
        self.status.t_bytes_u += len(data)

    def read_manifest(self, mid, dec):
        self.status.wait('Reading manifest %d' % (mid, ))
        k = Key(self.b)
        k.key = 'manifest.%s' % mid
        data = k.get_contents_as_string()
        self.status.unwait()
        self.status.t_bytes_d += len(data)
        return json.loads(dec(data))

    def list_manifest_ids(self):
        self.status.wait('Listing manifests...')
        manifestids = []
        for key in self.b.list(prefix='manifest.'):
            filepre, manifestid = key.key.split('.', 2)
            manifestids.append(int(manifestid))
        manifestids.sort()
        self.status.unwait()
        return manifestids
