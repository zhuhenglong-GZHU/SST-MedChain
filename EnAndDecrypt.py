import time
import hashlib
import secrets
from typing import Tuple

# Use ecdsa library for real elliptic curve operations
try:
    from ecdsa import SECP256k1
    from ecdsa.ellipticcurve import Point
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("Please install required libraries:")
    print("  pip install ecdsa pycryptodome")
    raise


class EnAndDecryptSimulator:
    def __init__(self):
        self.curve = SECP256k1
        self.generator = SECP256k1.generator
        self.order = SECP256k1.order

    def generate_keypair(self) -> Tuple[int, Point]:
        """Generate ECC keypair (SK, PK)"""
        private_key = secrets.randbelow(self.order - 1) + 1
        public_key = private_key * self.generator
        return private_key, public_key

    def kdf_sha256(self, point: Point) -> bytes:
        """Key Derivation Function using SHA256
        Input: ECC point
        Output: 32 bytes derived key material"""
        x_bytes = point.x().to_bytes(32, 'big')
        return hashlib.sha256(x_bytes).digest()

    def simulate_key_encapsulation(self, SK_H: int, w_i: Point, K_AES: bytes = None) -> Tuple[
        float, Tuple[Point, bytes, bytes, bytes]]:
        """
        Simulate symmetric key encapsulation process (Target Hospital side).

        According to Paper Section 4.1.4:
        - Combines public key: PK_Com = PK_H + w_i
        - Generates ephemeral point: R = r * g
        - Derives shared secret: S = r * PK_Com
        - Derives session key: K_session = KDF(S)
        - Encrypts with AES-GCM: (C, Tag) = AES-GCM_encrypt(K_session, IV, K_AES)

        Args:
            SK_H: Hospital private key
            w_i: Token point (consumed token)
            K_AES: Symmetric key to be encapsulated (optional, auto-generated if None)

        Returns:
            Tuple[elapsed_time_ms, (R, IV, C, Tag)]
        """
        start_time = time.perf_counter()

        # Compute hospital public key: PK_H = SK_H * g
        PK_H = SK_H * self.generator

        # Combine public keys: PK_Com = PK_H + w_i
        PK_Com = PK_H + w_i

        # Generate random ephemeral factor r ∈ Z_q
        r = secrets.randbelow(self.order - 1) + 1

        # Compute ephemeral point: R = r * g
        R = r * self.generator

        # Derive shared secret: S = r * PK_Com = r * (SK_H + s_i) * g
        S = r * PK_Com

        # Derive session key via KDF: K_session = KDF(S)
        K_session_full = self.kdf_sha256(S)
        K_session = K_session_full[:16]  # Use first 16 bytes for AES-128

        # Generate random initialization vector
        IV = get_random_bytes(16)

        # Prepare the symmetric key to be encapsulated
        if K_AES is None:
            K_AES = get_random_bytes(16)  # The EMR encryption key to be encapsulated

        # Encrypt using AES-GCM: (C, Tag) = AES-GCM_encrypt(K_session, IV, K_AES)
        cipher = AES.new(K_session, AES.MODE_GCM, nonce=IV)
        C, Tag = cipher.encrypt_and_digest(K_AES)

        end_time = time.perf_counter()
        elapsed_ms = (end_time - start_time) * 1000

        # Return encapsulation package: CT_{K_AES} = (R, IV, C, Tag)
        return elapsed_ms, (R, IV, C, Tag)

    def simulate_decryption(self, SK_H: int, s_i: int, R: Point,
                            IV: bytes, C: bytes, Tag: bytes) -> Tuple[float, bytes]:
        """
        Simulate symmetric key decapsulation process (Requesting Hospital side).

        According to Paper Section 4.1.4:
        - Reconstructs shared secret: S' = (SK_H + s_i) * R
        - Derives session key: K'_session = KDF(S')
        - Decrypts with AES-GCM: K_AES = AES-GCM_decrypt(K'_session, IV, C, Tag)

        Args:
            SK_H: Hospital private key
            s_i: Token secret (only known to authorized doctor)
            R: Ephemeral point from encapsulation
            IV: Initialization vector from encapsulation
            C: Ciphertext from encapsulation
            Tag: Authentication tag from encapsulation

        Returns:
            Tuple[elapsed_time_ms, K_AES (decapsulated key)]
        """
        start_time = time.perf_counter()

        # Compute combined private key: SK_Com = SK_H + s_i (mod q)
        SK_Com = (SK_H + s_i) % self.order

        # Reconstruct shared secret: S' = SK_Com * R = (SK_H + s_i) * R
        S_prime = SK_Com * R

        # Derive session key: K'_session = KDF(S')
        K_session_full = self.kdf_sha256(S_prime)
        K_session_prime = K_session_full[:16]  # Use first 16 bytes for AES-128

        # Decrypt using AES-GCM: K_AES = AES-GCM_decrypt(K'_session, IV, C, Tag)
        cipher = AES.new(K_session_prime, AES.MODE_GCM, nonce=IV)
        K_AES = cipher.decrypt_and_verify(C, Tag)

        end_time = time.perf_counter()
        elapsed_ms = (end_time - start_time) * 1000

        return elapsed_ms, K_AES

