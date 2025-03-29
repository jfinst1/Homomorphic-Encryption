import unittest
from crypto.homomorphic_encryption import HomomorphicEncryption
from gmpy2 import mpz

class TestHomomorphicEncryption(unittest.TestCase):

    def setUp(self):
        self.he = HomomorphicEncryption()

    def test_encryption_decryption(self):
        plaintext = mpz(42)
        encrypted = self.he.encrypt(plaintext)
        decrypted = self.he.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)

    def test_homomorphic_addition(self):
        plaintext1 = mpz(10)
        plaintext2 = mpz(20)
        encrypted_value1 = self.he.encrypt(plaintext1)
        encrypted_value2 = self.he.encrypt(plaintext2)
        homomorphic_sum = self.he.add_encrypted_values(encrypted_value1, encrypted_value2)
        self.he.check_homomorphic_operation(homomorphic_sum, mpz(plaintext1 + plaintext2))
        decrypted_sum = self.he.decrypt(homomorphic_sum)
        self.assertEqual(decrypted_sum, mpz(plaintext1 + plaintext2))

    def test_homomorphic_multiplication(self):
        plaintext = mpz(10)
        multiplier = mpz(3)
        encrypted_value = self.he.encrypt(plaintext)
        homomorphic_product = self.he.multiply_encrypted_values(encrypted_value, multiplier)
        self.he.check_homomorphic_operation(homomorphic_product, mpz(plaintext * multiplier))
        decrypted_product = self.he.decrypt(homomorphic_product)
        self.assertEqual(decrypted_product, mpz(plaintext * multiplier))

    def test_batch_encryption_decryption(self):
        plaintext_list = [10, 20, 30]
        encrypted_values = self.he.batch_encrypt(plaintext_list)
        decrypted_values = self.he.batch_decrypt(encrypted_values)
        self.assertEqual(decrypted_values, [mpz(v) for v in plaintext_list])

    def test_bootstrapping(self):
        plaintext = mpz(15)
        encrypted_value = self.he.encrypt(plaintext)
        bootstrapped_value = self.he.bootstrap(encrypted_value)
        self.he.check_homomorphic_operation(bootstrapped_value, plaintext)
        decrypted_bootstrapped = self.he.decrypt(bootstrapped_value)
        self.assertEqual(decrypted_bootstrapped, plaintext)

if __name__ == '__main__':
    unittest.main()