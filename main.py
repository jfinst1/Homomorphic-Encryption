from crypto.elliptic_curve import EllipticCurveCryptography
from crypto.homomorphic_encryption import HomomorphicEncryption
from crypto.quantum_operations import QuantumOperations
from utils.data_conversion import DataConversion
from utils.key_management import KeyManagement
from utils.error_handling import ErrorHandler
from gmpy2 import mpz

def main():
    # Initialize components
    error_handler = ErrorHandler()
    ecc = EllipticCurveCryptography(curve_name='secp256k1')
    he = HomomorphicEncryption()
    qo = QuantumOperations()
    converter = DataConversion()
    key_manager = KeyManagement()

    try:
        # --- Elliptic Curve Operations ---
        # Generate EC key pair
        error_handler.log_info("Generating EC key pair...")
        private_key, public_key = ecc.generate_key_pair()

        # Encrypt and decrypt data using ECIES
        plaintext = 42
        error_handler.log_info(f"Encrypting data using ECIES: {plaintext}")
        ephemeral_public_key, ciphertext = ecc.encrypt_with_ecies(public_key, plaintext)
        decrypted_plaintext = ecc.decrypt_with_ecies(private_key, ephemeral_public_key, ciphertext)
        error_handler.log_info(f"ECIES Decrypted Plaintext: {decrypted_plaintext}")

        # Sign and verify data
        data = b"Important data"
        error_handler.log_info("Signing data with private key...")
        signature = ecc.sign_data(private_key, data)
        ecc.verify_signature(public_key, signature, data)
        error_handler.log_info("Signature verified successfully.")

        # --- Homomorphic Encryption Operations ---
        # Homomorphic encryption with Paillier cryptosystem
        plaintext1 = mpz(10)
        plaintext2 = mpz(20)
        error_handler.log_info(f"Encrypting {plaintext1} and {plaintext2} using Homomorphic Encryption...")
        encrypted_value1 = he.encrypt(plaintext1)
        encrypted_value2 = he.encrypt(plaintext2)

        # Homomorphic addition
        error_handler.log_info("Performing homomorphic addition...")
        homomorphic_sum = he.add_encrypted_values(encrypted_value1, encrypted_value2)
        he.check_homomorphic_operation(homomorphic_sum, mpz(plaintext1 + plaintext2))
        decrypted_sum = he.decrypt(homomorphic_sum)
        error_handler.log_info(f"Homomorphic Sum (Decrypted): {decrypted_sum}")

        # Homomorphic multiplication
        error_handler.log_info("Performing homomorphic multiplication...")
        multiplier = mpz(3)
        homomorphic_product = he.multiply_encrypted_values(encrypted_value1, multiplier)
        he.check_homomorphic_operation(homomorphic_product, mpz(plaintext1 * multiplier))
        decrypted_product = he.decrypt(homomorphic_product)
        error_handler.log_info(f"Homomorphic Product (Decrypted): {decrypted_product}")

        # Batch encryption and decryption
        plaintext_list = [10, 20, 30]
        error_handler.log_info(f"Batch encrypting {plaintext_list}...")
        encrypted_values = he.batch_encrypt(plaintext_list)
        decrypted_values = he.batch_decrypt(encrypted_values)
        error_handler.log_info(f"Batch Decrypted Values: {decrypted_values}")

        # Optimize encryption parameters
        error_handler.log_info("Optimizing homomorphic encryption parameters...")
        he.optimize_parameters(new_key_size=3072)

        # --- Quantum Operations ---
        # Quantum encryption example
        quantum_data = converter.classical_to_quantum(42, 8)
        error_handler.log_info(f"Encrypting quantum data: {quantum_data}")
        quantum_encrypted_data = qo.quantum_encryption(quantum_data)
        quantum_corrected_data = qo.apply_error_correction(quantum_encrypted_data)
        error_handler.log_info(f"Quantum Encrypted Data: {quantum_corrected_data}")

        # Quantum key generation
        error_handler.log_info("Generating quantum key...")
        quantum_key = qo.quantum_key_generation()
        error_handler.log_info(f"Quantum Key: {quantum_key}")

        # --- Key Management ---
        # Save and load private/public keys
        error_handler.log_info("Saving and loading EC keys...")
        key_manager.save_key(private_key, 'private_key.pem')
        key_manager.save_key(public_key, 'public_key.pem')
        loaded_private_key = key_manager.load_private_key('private_key.pem')
        loaded_public_key = key_manager.load_public_key('public_key.pem')

        # Verify key integrity
        key_manager.verify_key_integrity(loaded_private_key, 'private_key.pem')
        key_manager.verify_key_integrity(loaded_public_key, 'public_key.pem')
        error_handler.log_info("Key integrity verified successfully.")

    except Exception as e:
        error_handler.context_aware_handling("Main Program", e)

if __name__ == "__main__":
    main()