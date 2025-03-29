import numpy as np
from cryptography.hazmat.primitives.asymmetric import ec

class DataConversion:
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve

    def plaintext_to_ecc_point(self, plaintext: int):
        x = plaintext % self.curve.curve().order
        point = ec.EllipticCurvePublicNumbers(x, x, self.curve).public_key()
        return point

    def ecc_point_to_plaintext(self, point):
        return point.public_numbers().x

    def classical_to_quantum(self, data: int, n_qubits: int):
        binary_data = format(data, f'0{n_qubits}b')
        quantum_state = np.array([int(bit) for bit in binary_data])
        return quantum_state

    def quantum_to_classical(self, quantum_state: np.ndarray):
        binary_data = ''.join(map(str, quantum_state.astype(int)))
        classical_data = int(binary_data, 2)
        return classical_data