
import flexceptions
import bz2

def init(config, compression = None):
    if 'compression' not in config:
        compression = 'bz2'
    if compression is not None:
        config['compression'] = compression

def compress(config, data):
    if config['compression'] == 'bz2':
        return b'bz2' + bz2.compress(data)
    if config['compression'] == 'none':
        return b'off' + data
    raise flexceptions.CompressionError

def decompress(config, data):
    if data[:3] == b'bz2':
        return bz2.decompress(data[3:])
    if data[:3] == b'off':
        return data[3:]
    raise flexeptions.BlockCorruptionError
