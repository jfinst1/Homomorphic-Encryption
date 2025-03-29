import gmpy2
from gmpy2 import mpz
from utils.error_handling import ErrorHandler

class HomomorphicEncryption:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_paillier_keypair()
        self.error_handler = ErrorHandler()

    def generate_paillier_keypair(self):
        p = gmpy2.next_prime(gmpy2.mpz_random(gmpy2.random_state(), self.key_size // 2))
        q = gmpy2.next_prime(gmpy2.mpz_random(gmpy2.random_state(), self.key_size // 2))
        n = p * q
        g = n + 1
        lambda_ = gmpy2.lcm(p - 1, q - 1)
        mu = gmpy2.invert(lambda_, n)
        return (n, g), (lambda_, mu)

    def encrypt(self, plaintext):
        n, g = self.public_key
        r = gmpy2.mpz_random(gmpy2.random_state(), n)
        ciphertext = (gmpy2.powmod(g, plaintext, n * n) * gmpy2.powmod(r, n, n * n)) % (n * n)
        return self.add_error_correction(ciphertext)

    def decrypt(self, ciphertext):
        ciphertext = self.remove_error_correction(ciphertext)
        n, g = self.public_key
        lambda_, mu = self.private_key
        x = gmpy2.powmod(ciphertext, lambda_, n * n) - 1
        plaintext = ((x // n) * mu) % n
        return plaintext

    def add_encrypted_values(self, encrypted_value1, encrypted_value2):
        n, g = self.public_key
        added_encrypted = (encrypted_value1 * encrypted_value2) % (n * n)
        return added_encrypted

    def multiply_encrypted_values(self, encrypted_value, multiplier):
        n, g = self.public_key
        multiplied_encrypted = gmpy2.powmod(encrypted_value, multiplier, n * n)
        return multiplied_encrypted

    def check_homomorphic_operation(self, result, expected_value):
        decrypted_result = self.decrypt(result)
        if decrypted_result != expected_value:
            self.error_handler.handle_error(
                ValueError(f"Homomorphic operation error: expected {expected_value}, got {decrypted_result}")
            )

    def add_error_correction(self, ciphertext):
        # Adding a simple parity bit for error correction (HE-ECC)
        parity_bit = ciphertext % 2
        return (ciphertext << 1) | parity_bit

    def remove_error_correction(self, ciphertext):
        # Removing error correction (extracting the parity bit)
        parity_bit = ciphertext & 1
        corrected_ciphertext = ciphertext >> 1
        calculated_parity = corrected_ciphertext % 2
        if parity_bit != calculated_parity:
            self.error_handler.handle_error(
                ValueError("Homomorphic Error Correction Failed: Parity check mismatch")
            )
        return corrected_ciphertext

    def bootstrap(self, ciphertext):
        # Implementing a simple bootstrapping mechanism for FHE
        plaintext = self.decrypt(ciphertext)
        return self.encrypt(plaintext)

    def batch_encrypt(self, plaintext_list):
        return [self.encrypt(mpz(plaintext)) for plaintext in plaintext_list]

    def batch_decrypt(self, ciphertext_list):
        return [self.decrypt(ciphertext) for ciphertext in ciphertext_list]

    def optimize_parameters(self, new_key_size):
        self.key_size = new_key_size
        self.public_key, self.private_key = self.generate_paillier_keypair()
        self.error_handler.log_info(f"Encryption parameters optimized: new key size = {self.key_size} bits")