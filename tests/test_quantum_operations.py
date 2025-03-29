import unittest
from crypto.quantum_operations import QuantumOperations
from utils.data_conversion import DataConversion

class TestQuantumOperations(unittest.TestCase):

    def test_quantum_encryption(self):
        qo = QuantumOperations()
        converter = DataConversion()
        data = converter.classical_to_quantum(42, 8)
        quantum_encrypted_data = qo.quantum_encryption(data)
        self.assertIsNotNone(quantum_encrypted_data)

    def test_quantum_key_generation(self):
        qo = QuantumOperations()
        quantum_key = qo.quantum_key_generation()
        self.assertIsNotNone(quantum_key)

if __name__ == '__main__':
    unittest.main()