
import os
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random
import bz2
from struct import pack, unpack, calcsize

from flexceptions import EncryptionError

class NullEncryption:
    def set_key(self, key):
        self.key = key

    def encrypt(self, plaintext):
        return plaintext

    def decrypt(self, ciphertext):
        return ciphertext
    
    def decompress(self, data):
        try:
            return bz2.decompress(data)
        except IOError:
            return data

    def compress(self,data):
        return bz2.compress(data)

    def encrypt_manifest(self, plaintext):
        return self.compress(plaintext)

    def decrypt_manifest(self, ciphertext):
        return self.decompress(ciphertext)

class AES256Encryption(NullEncryption):
    def __init__(self, passphrase):
        self.passphrase = passphrase
        self.salt = None
        self.ready = False
        self.hmac_size = SHA256.SHA256Hash.digest_size

    def check_hmac(self, msg, hmac):
        return HMAC.new(self.hmac_key, msg, SHA256).digest() == hmac or \
               HMAC.new(self.key, msg, SHA256).digest() == hmac

    def hmac(self, msg):
        return HMAC.new(self.hmac_key, msg, SHA256).digest()
        
    def set_key(self, salt = None):
        if salt is None:
            if self.salt is None:
                salt = Random.new().read(8) # 64-bit salt
            else:
                salt = self.salt
        pbkdf2 = PBKDF2(self.passphrase, salt)
        self.key = pbkdf2.read(32)
        self.hmac_key = pbkdf2.read(32)
        del self.passphrase
        self.ready = True
        self.salt = salt
        return salt

    def encrypt(self, plaintext):
        if not self.ready:
            self.set_key()
        plaintext = pack('<Q', len(plaintext)) + plaintext
        needed_padding = 256 - (len(plaintext) % 256)
        if needed_padding == 256:
            needed_padding = 0
        plaintext = plaintext + (b' ' * needed_padding)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key,
                         mode = AES.MODE_CBC,
                         IV=iv)
        return iv + cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        iv, ciphertext = (ciphertext[:AES.block_size],
                          ciphertext[AES.block_size:])
        cipher = AES.new(self.key,
                         mode = AES.MODE_CBC,
                         IV=iv)
        plaintext = cipher.decrypt(ciphertext)
        length, plaintext = (unpack('<Q', plaintext[:8])[0],
                             plaintext[8:])
        return plaintext[:length]

    def encrypt_manifest(self, plaintext):
        if not self.ready:
            self.set_key()
        ciphertext = self.encrypt(self.compress(plaintext))
        hmac = self.hmac(ciphertext)
        return self.salt + hmac + ciphertext
        
    def decrypt_manifest(self, ciphertext):
        salt, ciphertext = ciphertext[:8], ciphertext[8:]
        if not self.ready:
            self.set_key(salt)
        hmac, msg = ciphertext[:self.hmac_size], ciphertext[self.hmac_size:]
        if not self.check_hmac(msg, hmac):
            raise EncryptionError
        return self.decompress(self.decrypt(msg))
        
