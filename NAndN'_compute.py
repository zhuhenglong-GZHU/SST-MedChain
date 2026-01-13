import time
import hashlib
import secrets
import statistics
from typing import Tuple

# Use ecdsa library for real elliptic curve operations
try:
    from ecdsa import SECP256k1
    from ecdsa.ellipticcurve import Point
except ImportError:
    print("Please install ecdsa library: pip install ecdsa matplotlib")
    raise


class NIDOTSimulator:
    def __init__(self):
        self.curve = SECP256k1
        self.generator = SECP256k1.generator
        self.order = SECP256k1.order

    def generate_keypair(self) -> Tuple[int, Point]:
        private_key = secrets.randbelow(self.order - 1) + 1
        public_key = private_key * self.generator
        return private_key, public_key

    def kdf_sha256(self, point: Point) -> bytes:
        x_bytes = point.x().to_bytes(32, 'big')
        return hashlib.sha256(x_bytes).digest()

    def aes_gcm_simulate(self, data_len=1024):
        hashlib.sha256(secrets.token_bytes(data_len)).digest()

    def simulate_patient_N(self, PK_D: Point) -> float:
        start_time = time.perf_counter()
        r = secrets.randbelow(self.order - 1) + 1
        R = r * self.generator
        S = r * PK_D
        N = self.kdf_sha256(S)
        c = hashlib.sha256(N).digest()
        end_time = time.perf_counter()
        return (end_time - start_time) * 1000

    def simulate_doctor_N_prime(self, SK_D: int, R: Point) -> float:
        start_time = time.perf_counter()
        S_prime = SK_D * R
        N_prime = self.kdf_sha256(S_prime)
        end_time = time.perf_counter()
        return (end_time - start_time) * 1000
