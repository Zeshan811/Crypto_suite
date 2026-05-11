"""
Cryptographic Algorithms Implementation
Supports: Triple DES, AES, RSA, Elliptic Curve Cryptography (ECC), ElGamal
"""

import os
import time
import base64
import hashlib
import secrets
from Crypto.Cipher import DES3, AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ─────────────────────────────────────────────
# 1. TRIPLE DES (3DES)
# ─────────────────────────────────────────────
class TripleDESCrypto:
    KEY_SIZE = 24  # 192-bit key

    @staticmethod
    def generate_key() -> bytes:
        while True:
            key = get_random_bytes(24)
            try:
                DES3.adjust_key_parity(key)
                return key
            except Exception:
                continue

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        iv = get_random_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded = pad(data, DES3.block_size)
        return iv + cipher.encrypt(padded)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        iv = data[:8]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = cipher.decrypt(data[8:])
        return unpad(decrypted, DES3.block_size)


# ─────────────────────────────────────────────
# 2. AES (Advanced Encryption Standard)
# ─────────────────────────────────────────────
class AESCrypto:
    KEY_SIZE = 32  # 256-bit

    @staticmethod
    def generate_key() -> bytes:
        return get_random_bytes(32)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(data, AES.block_size)
        return iv + cipher.encrypt(padded)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        iv = data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data[16:])
        return unpad(decrypted, AES.block_size)


# ─────────────────────────────────────────────
# 3. RSA
# ─────────────────────────────────────────────
class RSACrypto:
    KEY_SIZE = 2048

    @staticmethod
    def generate_keypair():
        key = RSA.generate(2048)
        return key.export_key(), key.publickey().export_key()

    @staticmethod
    def encrypt(data: bytes, public_key: bytes) -> bytes:
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        # RSA can only encrypt small chunks — chunk for large data
        max_chunk = 190
        chunks = [data[i:i+max_chunk] for i in range(0, len(data), max_chunk)]
        encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
        # Prefix with 4-byte count of chunks
        result = len(encrypted_chunks).to_bytes(4, 'big')
        for chunk in encrypted_chunks:
            result += len(chunk).to_bytes(4, 'big') + chunk
        return result

    @staticmethod
    def decrypt(data: bytes, private_key: bytes) -> bytes:
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        num_chunks = int.from_bytes(data[:4], 'big')
        pos = 4
        chunks = []
        for _ in range(num_chunks):
            chunk_len = int.from_bytes(data[pos:pos+4], 'big')
            pos += 4
            chunk = data[pos:pos+chunk_len]
            pos += chunk_len
            chunks.append(cipher.decrypt(chunk))
        return b''.join(chunks)


# ─────────────────────────────────────────────
# 4. Elliptic Curve Cryptography (ECIES-style)
# ─────────────────────────────────────────────
# Pure-Python implementation over a simple named curve (secp256k1-like params)

class ECPoint:
    """Point on elliptic curve y^2 = x^3 + ax + b mod p"""
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        return f"ECPoint({self.x}, {self.y})"


class EllipticCurve:
    """Short Weierstrass curve: y^2 = x^3 + ax + b (mod p)"""
    # Using secp256r1 (NIST P-256) parameters
    p  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    n  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    def __init__(self):
        self.G = ECPoint(self.Gx, self.Gy, self)
        self.INF = ECPoint(None, None, self)

    def add(self, P, Q):
        if P.is_infinity(): return Q
        if Q.is_infinity(): return P
        if P.x == Q.x:
            if P.y != Q.y:
                return self.INF
            return self.double(P)
        lam = (Q.y - P.y) * pow(Q.x - P.x, -1, self.p) % self.p
        x3 = (lam*lam - P.x - Q.x) % self.p
        y3 = (lam*(P.x - x3) - P.y) % self.p
        return ECPoint(x3, y3, self)

    def double(self, P):
        if P.is_infinity(): return P
        lam = (3*P.x*P.x + self.a) * pow(2*P.y, -1, self.p) % self.p
        x3 = (lam*lam - 2*P.x) % self.p
        y3 = (lam*(P.x - x3) - P.y) % self.p
        return ECPoint(x3, y3, self)

    def scalar_mult(self, k, P):
        R = self.INF
        Q = ECPoint(P.x, P.y, self)
        while k:
            if k & 1:
                R = self.add(R, Q)
            Q = self.double(Q)
            k >>= 1
        return R


class ECCCrypto:
    """ECIES: hybrid encryption using EC key exchange + AES"""

    def __init__(self):
        self.curve = EllipticCurve()

    def generate_keypair(self):
        private_key = secrets.randbelow(self.curve.n - 1) + 1
        public_point = self.curve.scalar_mult(private_key, self.curve.G)
        pub = f"{public_point.x},{public_point.y}".encode()
        priv = str(private_key).encode()
        return priv, pub

    def _derive_key(self, shared_point: ECPoint) -> bytes:
        raw = shared_point.x.to_bytes(32, 'big')
        return hashlib.sha256(raw).digest()

    def encrypt(self, data: bytes, public_key: bytes) -> bytes:
        x_str, y_str = public_key.decode().split(',')
        pub = ECPoint(int(x_str), int(y_str), self.curve)

        r = secrets.randbelow(self.curve.n - 1) + 1
        R = self.curve.scalar_mult(r, self.curve.G)
        shared = self.curve.scalar_mult(r, pub)
        aes_key = self._derive_key(shared)

        # AES-CBC encrypt
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, 16))

        # Pack: Rx(32) + Ry(32) + iv(16) + ciphertext
        header = R.x.to_bytes(32, 'big') + R.y.to_bytes(32, 'big') + iv
        return header + ct

    def decrypt(self, data: bytes, private_key: bytes) -> bytes:
        priv = int(private_key.decode())
        Rx = int.from_bytes(data[:32], 'big')
        Ry = int.from_bytes(data[32:64], 'big')
        R = ECPoint(Rx, Ry, self.curve)
        iv = data[64:80]
        ct = data[80:]

        shared = self.curve.scalar_mult(priv, R)
        aes_key = self._derive_key(shared)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 16)


# ─────────────────────────────────────────────
# 5. ElGamal
# ─────────────────────────────────────────────
class ElGamalCrypto:
    """ElGamal over a large safe prime — hybrid mode with AES for bulk data"""

    # 1024-bit safe prime (p = 2q+1)
    P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF", 16
    )
    G = 2

    def generate_keypair(self):
        p = self.P
        x = secrets.randbelow(p - 2) + 2          # private key
        y = pow(self.G, x, p)                      # public key
        priv = str(x).encode()
        pub = str(y).encode()
        return priv, pub

    def _elgamal_encrypt_int(self, m: int, y: int, p: int) -> tuple:
        k = secrets.randbelow(p - 2) + 2
        c1 = pow(self.G, k, p)
        c2 = (m * pow(y, k, p)) % p
        return c1, c2

    def _elgamal_decrypt_int(self, c1: int, c2: int, x: int, p: int) -> int:
        s = pow(c1, x, p)
        s_inv = pow(s, -1, p)
        return (c2 * s_inv) % p

    def encrypt(self, data: bytes, public_key: bytes) -> bytes:
        y = int(public_key.decode())
        p = self.P

        # Hybrid: encrypt a random AES key via ElGamal, use AES for data
        aes_key_int = secrets.randbelow(2**256)
        aes_key = aes_key_int.to_bytes(32, 'big')

        # Ensure aes_key_int < p
        m = aes_key_int % p
        c1, c2 = self._elgamal_encrypt_int(m, y, p)

        # AES-CBC encrypt data
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, 16))

        # Serialize c1, c2 as 128-byte big-endian ints
        blob = (
            c1.to_bytes(128, 'big') +
            c2.to_bytes(128, 'big') +
            iv + ct
        )
        return blob

    def decrypt(self, data: bytes, private_key: bytes) -> bytes:
        x = int(private_key.decode())
        p = self.P

        c1 = int.from_bytes(data[:128], 'big')
        c2 = int.from_bytes(data[128:256], 'big')
        iv = data[256:272]
        ct = data[272:]

        m = self._elgamal_decrypt_int(c1, c2, x, p)
        aes_key = m.to_bytes(32, 'big')

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 16)


# ─────────────────────────────────────────────
# Performance Benchmarking
# ─────────────────────────────────────────────
def benchmark_algorithm(algo_name: str, data_sizes_kb: list = None) -> dict:
    """Benchmark encryption/decryption for a given algorithm across data sizes."""
    if data_sizes_kb is None:
        data_sizes_kb = [1, 10, 100]

    results = {}

    for size_kb in data_sizes_kb:
        data = os.urandom(size_kb * 1024)
        enc_time = dec_time = 0

        if algo_name == "Triple DES":
            key = TripleDESCrypto.generate_key()
            t0 = time.perf_counter(); ct = TripleDESCrypto.encrypt(data, key); enc_time = time.perf_counter()-t0
            t0 = time.perf_counter(); TripleDESCrypto.decrypt(ct, key);         dec_time = time.perf_counter()-t0

        elif algo_name == "AES":
            key = AESCrypto.generate_key()
            t0 = time.perf_counter(); ct = AESCrypto.encrypt(data, key); enc_time = time.perf_counter()-t0
            t0 = time.perf_counter(); AESCrypto.decrypt(ct, key);        dec_time = time.perf_counter()-t0

        elif algo_name == "RSA":
            # RSA is slow for large data — cap at 1 KB for benchmark
            bench_data = data[:1024]
            priv, pub = RSACrypto.generate_keypair()
            t0 = time.perf_counter(); ct = RSACrypto.encrypt(bench_data, pub); enc_time = time.perf_counter()-t0
            t0 = time.perf_counter(); RSACrypto.decrypt(ct, priv);              dec_time = time.perf_counter()-t0

        elif algo_name == "ECC":
            ecc = ECCCrypto()
            priv, pub = ecc.generate_keypair()
            t0 = time.perf_counter(); ct = ecc.encrypt(data, pub); enc_time = time.perf_counter()-t0
            t0 = time.perf_counter(); ecc.decrypt(ct, priv);       dec_time = time.perf_counter()-t0

        elif algo_name == "ElGamal":
            eg = ElGamalCrypto()
            priv, pub = eg.generate_keypair()
            t0 = time.perf_counter(); ct = eg.encrypt(data, pub); enc_time = time.perf_counter()-t0
            t0 = time.perf_counter(); eg.decrypt(ct, priv);       dec_time = time.perf_counter()-t0

        results[f"{size_kb}KB"] = {
            "encrypt_ms": round(enc_time * 1000, 3),
            "decrypt_ms": round(dec_time * 1000, 3),
            "total_ms":   round((enc_time + dec_time) * 1000, 3),
        }

    return results
