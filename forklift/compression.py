
import flexceptions
import bz2


def init(config, compression=None):
    if 'compression' not in config:
        compression = 'bz2'
    if compression is not None:
        config['compression'] = compression


def compress(config, data):
    if config['compression'] == 'bz2':
        compressed = bz2.compress(data)
        if len(compressed) < data:
            return b'bz2' + bz2.compress(data)
        else:  # bz2'ed random data is larger than not
            return b'off' + data
    if config['compression'] == 'off':
        return b'off' + data
    raise flexceptions.CompressionError


def decompress(config, data):
    if data[:3] == b'bz2':
        return bz2.decompress(data[3:])
    if data[:3] == b'off':
        return data[3:]
    raise flexceptions.BlockCorruptionError
