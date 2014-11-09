
from transport import Transport, TryAgain, Fail, NotRedundant
from local_transport import LocalTransport
from aws_transports import S3Transport, S3GlacierTransport, boto
from sqlite_transport import SQLiteTransport


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

        elif t_config['type'] == 'sqlite':
            # Using the split option creates another MetaTransport with
            # multiple sqlite transports. This guards against very big files
            # in filesystems that don't support it
            if 'split' in t_config:
                dests = []
                for n in range(t_config['split']):
                    dests.append({'type': 'sqlite',
                                  'path': '{}.{}'.format(t_config['path'],
                                                         n)})
                return MetaTransport({'redundancy': 1,
                                      'destination': dests
                                     }, status)

            return SQLiteTransport(t_config['path'], status)

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
