from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import hmac
from utils.error_handling import ErrorHandler

class EllipticCurveCryptography:
    def __init__(self, curve_name='secp256r1'):
        self.curve = self.get_curve(curve_name)
        self.error_handler = ErrorHandler()

    def get_curve(self, curve_name):
        curves = {
            'secp256r1': ec.SECP256R1(),
            'secp256k1': ec.SECP256K1(),
            'ed25519': ec.Ed25519()
        }
        if curve_name in curves:
            return curves[curve_name]
        else:
            self.error_handler.handle_error(ValueError(f"Unsupported curve: {curve_name}"))

    def generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve, default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt(self, public_key, plaintext, associated_data=b""):
        shared_key = public_key.exchange(ec.ECDH(), public_key)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(shared_key)
        
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')) + encryptor.finalize()
        
        return (salt, iv, encryptor.tag, ciphertext)

    def decrypt(self, private_key, ciphertext, associated_data=b""):
        salt, iv, tag, encrypted_data = ciphertext
        shared_key = private_key.exchange(ec.ECDH(), private_key.public_key())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(shared_key)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return int.from_bytes(decrypted_data, 'big')

    def point_addition(self, point1, point2):
        new_x = (point1.x + point2.x) % self.curve.curve().order
        new_y = (point1.y + point2.y) % self.curve.curve().order
        return ec.EllipticCurvePublicNumbers(new_x, new_y, self.curve).public_key(default_backend())

    def sign_data(self, private_key, data):
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA512())
        )
        return signature

    def verify_signature(self, public_key, signature, data):
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA512())
        )

    def encrypt_with_ecies(self, public_key, plaintext):
        ephemeral_key = ec.generate_private_key(self.curve, default_backend())
        shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(shared_key)
        
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')) + encryptor.finalize()
        return ephemeral_key.public_key(), (salt, iv, encryptor.tag, ciphertext)

    def decrypt_with_ecies(self, private_key, ephemeral_public_key, ciphertext):
        salt, iv, tag, encrypted_data = ciphertext
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(shared_key)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return int.from_bytes(decrypted_data, 'big')

    def derive_key_from_passphrase(self, passphrase, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())
        return key, salt