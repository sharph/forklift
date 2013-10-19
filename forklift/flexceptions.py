

class EncryptionError(Exception):
    pass

class BlockCorruptionError(Exception):
    pass

class ManifestCorruptionError(Exception):
    pass

class ChunkWriteError(Exception):
    pass

class ChunkReadError(Exception):
    pass
