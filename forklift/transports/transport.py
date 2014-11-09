from time import sleep


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
