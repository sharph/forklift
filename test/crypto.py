#!/usr/bin/env python

import sys
import unittest
from base64 import b64decode as b64d

sys.path.append('..')

from forklift import crypto

class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.config = {}
        crypto.init(self.config)

    def tearDown(self):
        self.config = None

    def test_init(self):
        """
        `init` function should populate config with a 256 bit key
        that is randomly generated
        """
        self.assertEqual(len(b64d(self.config['aes_key'])), 256 / 8)
        keya = b64d(self.config['aes_key'])
        config = {}
        crypto.init(config)
        self.assertEqual(len(b64d(config['aes_key'])), 256 / 8)
        keyb = b64d(config['aes_key'])
        self.assertNotEqual(keya, keyb)

    def test_aes_encrypt_iv(self):
        """
        `aes_encrypt` should return different values for the same
        key and plaintext as an IV should be used
        """
        plaintext = "Hello, world!"
        ciphertexta = crypto.aes_encrypt(self.config, plaintext)
        ciphertextb = crypto.aes_encrypt(self.config, plaintext)
        self.assertNotEqual(ciphertexta, ciphertextb)

    def test_aes_decrypt(self):
        """
        Output from `aes_decrypt` should match the input to
        aes_encrypt
        """
        plaintext = "Hello, world!"
        ciphertext = crypto.aes_encrypt(self.config, plaintext)
        decrypted_plaintext = crypto.aes_decrypt(self.config, ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext)

    def test_aes_decrypt_fail(self):
        """
        `aes_decrypt` should fail when an incorrect key is provided
        """
        plaintext = "Hello Alice!"
        ciphertext = crypto.aes_encrypt(self.config, plaintext)
        bad_config = {}
        crypto.init(bad_config)
        bad_ciphertext = crypto.aes_decrypt(bad_config, ciphertext)
        self.assertNotEqual(ciphertext, bad_ciphertext)

    def test_auth_then_decrypt(self):
        """
        Output from `auth_then_decrypt` should match the input to
        `encrypt_then_mac`
        """
        plaintext = "Hello Bob!"
        ciphertext = crypto.encrypt_then_mac(self.config, plaintext)
        decrypted_plaintext = crypto.auth_then_decrypt(self.config,
                                                       ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext)

    def test_auth_then_decypt_fail_on_tamper(self):
        """
        `auth_then_decrypt` should raise an exception of ciphertext
        is tampered with
        """
        plaintext = "Purity of essence!"
        ciphertext = crypto.encrypt_then_mac(self.config, plaintext)
        tampered_ciphertext = ciphertext[:-5] + '.....'
        with self.assertRaises(crypto.EncryptionError):
            crypto.auth_then_decrypt(self.config, tampered_ciphertext)

    def test_decrypt_config(self):
        """
        `decrypt_config` should be able to decrypt a configuration using
        a passphrase
        """
        config_data = 'A little dog named Snuggles'
        passphrase = 'Password123'
        crypto.new_passphrase(self.config, passphrase)
        ciphertext = crypto.encrypt_config(self.config, config_data)
        decrypted_plaintext = crypto.decrypt_config(ciphertext, passphrase)
        self.assertEqual(config_data, decrypted_plaintext)

    def test_decrypt_config_bad_passphrase(self):
        """
        `decrypt_config` should fail when the password is incorrect
        """
        config_data = 'No other possibility'
        passphrase = 'correct horse battery staple'
        bad_passphrase = 'god'
        crypto.new_passphrase(self.config, passphrase)
        ciphertext = crypto.encrypt_config(self.config, config_data)
        with self.assertRaises(crypto.EncryptionError):
            decrypted_plaintext = crypto.decrypt_config(ciphertext,
                                                        bad_passphrase)



if __name__ == '__main__':
    unittest.main()
