
import flexceptions
import bz2

COMPRESSORS = {b'off': lambda x: x}
DECOMPRESSORS = {b'off': lambda x: x}

BEST = b'off'

try:
    import bz2
    COMPRESSORS[b'bz2'] = lambda x: bz2.compress(x)
    DECOMPRESSORS[b'bz2'] = lambda x: bz2.decompress(x)
    BEST = b'bz2'
except ImportError:
    pass

try:
    import zstd
    COMPRESSORS[b'zst'] = lambda x: zst.compress(x)
    DECOMPRESSORS[b'zst'] = lambda x: zst.decompress(x)
    BEST = b'zst'
except ImportError:
    pass


def init(config, compression=None):
    if 'compression' not in config:
        compression = BEST
    if compression is not None:
        config['compression'] = compression

def compress(config, data):
    compression = bytes(config['compression'])
    compressed = COMPRESSORS[compression](data)
    if len(compressed) < len(data):
        return compression + compressed
    else:  # bz2'ed random data is larger than not
        return b'off' + COMPRESSORS[b'off'](data)

def decompress(config, data):
    return DECOMPRESSORS[data[:3]](data[3:])
