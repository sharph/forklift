
import os
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random
import bz2
from struct import pack, unpack, calcsize
from base64 import b64decode as b64d
from base64 import b64encode as b64e

from flexceptions import EncryptionError

def init(config, crypto = 'aes'):
    if 'crypto' in config:
        crypto = config['crypto']
    config['crypto'] = crypto
    rng = Random.new()
    if 'aes_key' not in config:
        config['aes_key'] = b64e(rng.read(32)) # AES256
    if 'sha256hmac_key' not in config:
        config['sha256hmac_key'] = b64e(rng.read(SHA256.digest_size))

def aes_encrypt(config, plaintext):
    plaintext = pack('<Q', len(plaintext)) + plaintext
    needed_padding = 256 - (len(plaintext) % 256)
    if needed_padding == 256:
        needed_padding = 0
    plaintext = plaintext + (b' ' * needed_padding)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(b64d(config['aes_key']),
                     mode = AES.MODE_CBC,
                     IV=iv)
    ciphertext = iv + cipher.encrypt(plaintext)
    return ciphertext

def aes_decrypt(config, ciphertext):
    iv, ciphertext = (ciphertext[:AES.block_size],
                      ciphertext[AES.block_size:])
    cipher = AES.new(b64d(config['aes_key']),
                     mode = AES.MODE_CBC,
                     IV=iv)
    plaintext = cipher.decrypt(ciphertext)
    length, plaintext = (unpack('<Q', plaintext[:8])[0],
                         plaintext[8:])
    return plaintext[:length]

def encrypt(config, plaintext):
    return b'aes' + aes_encrypt(config, plaintext)

def decrypt(config, ciphertext):
    if ciphertext[:3] == b'aes':
        return aes_decrypt(config, ciphertext[3:])
    raise EncryptionError

def hmac(config, message):
    return HMAC.new(b64d(config['sha256hmac_key']),
                    message,
                    SHA256).digest()

def encrypted_hmac(config, plaintext):
    pass

def encrypt_then_mac(config, plaintext):
    ciphertext = encrypt(config, plaintext)
    return b'sh2' + hmac(config, ciphertext) + ciphertext

def auth_then_decrypt(config, ciphertext):
    if ciphertext[:3] != 'sh2':
        raise EncryptionError
    ciphertext = ciphertext[3:]
    digest, ciphertext = ciphertext[:SHA256.digest_size], \
                         ciphertext[SHA256.digest_size:]

    if hmac(config, ciphertext) != digest:
        raise EncryptionError
    return decrypt(config, ciphertext)

def new_passphrase(config, passphrase):
    salt = Random.new().read(8) # 64-bit salt
    pbkdf2 = PBKDF2(passphrase, salt)
    config['passphrase_salt'] = b64e(salt)
    config['passphrase_aes_key'] = b64e(pbkdf2.read(32)) # AES256
    config['passphrase_sha256hmac_key'] = b64e(pbkdf2.read(
                                                SHA256.digest_size))

    
#    def set_key(self, salt = None):
#        if salt is None:
#            if self.salt is None:
#                salt = Random.new().read(8) # 64-bit salt
#            else:
#                salt = self.salt
#        pbkdf2 = PBKDF2(self.passphrase, salt)
#        self.key = pbkdf2.read(32)
#        self.hmac_key = pbkdf2.read(32)
#        del self.passphrase
#        self.ready = True
#        self.salt = salt
#        return salt
#
#
#    def encrypt_manifest(self, plaintext):
#        if not self.ready:
#            self.set_key()
#        ciphertext = self.encrypt(self.compress(plaintext))
#        hmac = self.hmac(ciphertext)
#        return self.salt + hmac + ciphertext
#        
#    def decrypt_manifest(self, ciphertext):
#        salt, ciphertext = ciphertext[:8], ciphertext[8:]
#        if not self.ready:
#            self.set_key(salt)
#        hmac, msg = ciphertext[:self.hmac_size], ciphertext[self.hmac_size:]
#        if not self.check_hmac(msg, hmac):
#            raise EncryptionError
#        return self.decompress(self.decrypt(msg))
        
