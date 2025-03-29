import unittest
from crypto.elliptic_curve import EllipticCurveCryptography
from cryptography.hazmat.primitives.asymmetric import ec

class TestEllipticCurveCryptography(unittest.TestCase):

    def setUp(self):
        self.ecc = EllipticCurveCryptography(curve_name='secp256k1')
        self.private_key, self.public_key = self.ecc.generate_key_pair()

    def test_key_generation(self):
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)

    def test_ecies_encryption_decryption(self):
        plaintext = 42
        ephemeral_public_key, ciphertext = self.ecc.encrypt_with_ecies(self.public_key, plaintext)
        decrypted_plaintext = self.ecc.decrypt_with_ecies(self.private_key, ephemeral_public_key, ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext)

    def test_signature_verification(self):
        data = b"Test data"
        signature = self.ecc.sign_data(self.private_key, data)
        try:
            self.ecc.verify_signature(self.public_key, signature, data)
        except Exception:
            self.fail("Signature verification failed")

    def test_derive_key_from_passphrase(self):
        passphrase = "super_secret"
        key, salt = self.ecc.derive_key_from_passphrase(passphrase)
        self.assertEqual(len(key), 32)

if __name__ == '__main__':
    unittest.main()