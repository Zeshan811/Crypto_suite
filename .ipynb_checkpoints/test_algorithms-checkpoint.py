#!/usr/bin/env python3
"""
Quick verification test for all 5 cryptographic algorithms.
Run: python test_algorithms.py
"""
import sys
import os

# Allow running from any directory
sys.path.insert(0, os.path.dirname(__file__))

from crypto_algorithms import (
    TripleDESCrypto, AESCrypto, RSACrypto,
    ECCCrypto, ElGamalCrypto, benchmark_algorithm
)

TEST_DATA = b"Hello, CryptoSuite! This is a test message for all algorithms. " * 10
PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"


def test(name, encrypt_fn, decrypt_fn, key_fn):
    try:
        key = key_fn()
        ct  = encrypt_fn(TEST_DATA, key)
        pt  = decrypt_fn(ct, key)
        ok  = pt == TEST_DATA
        print(f"  {PASS if ok else FAIL}  {name}  ({len(ct)} bytes encrypted)")
        return ok
    except Exception as e:
        print(f"  {FAIL}  {name}: {e}")
        return False


print("\n" + "="*55)
print("  CryptoSuite — Algorithm Verification Tests")
print("="*55)

results = []

# Triple DES
results.append(test(
    "Triple DES",
    TripleDESCrypto.encrypt, TripleDESCrypto.decrypt,
    TripleDESCrypto.generate_key
))

# AES
results.append(test(
    "AES-256-CBC",
    AESCrypto.encrypt, AESCrypto.decrypt,
    AESCrypto.generate_key
))

# RSA
print("  Testing RSA (key generation may take a moment)...")
try:
    priv, pub = RSACrypto.generate_keypair()
    ct = RSACrypto.encrypt(TEST_DATA, pub)
    pt = RSACrypto.decrypt(ct, priv)
    ok = pt == TEST_DATA
    print(f"  {PASS if ok else FAIL}  RSA-2048-OAEP")
    results.append(ok)
except Exception as e:
    print(f"  {FAIL}  RSA: {e}")
    results.append(False)

# ECC
print("  Testing ECC (P-256 ECIES)...")
try:
    ecc = ECCCrypto()
    priv, pub = ecc.generate_keypair()
    ct = ecc.encrypt(TEST_DATA, pub)
    pt = ecc.decrypt(ct, priv)
    ok = pt == TEST_DATA
    print(f"  {PASS if ok else FAIL}  ECC P-256 ECIES")
    results.append(ok)
except Exception as e:
    print(f"  {FAIL}  ECC: {e}")
    results.append(False)

# ElGamal
print("  Testing ElGamal (hybrid mode)...")
try:
    eg = ElGamalCrypto()
    priv, pub = eg.generate_keypair()
    ct = eg.encrypt(TEST_DATA, pub)
    pt = eg.decrypt(ct, priv)
    ok = pt == TEST_DATA
    print(f"  {PASS if ok else FAIL}  ElGamal (hybrid)")
    results.append(ok)
except Exception as e:
    print(f"  {FAIL}  ElGamal: {e}")
    results.append(False)

print()
print(f"  Results: {sum(results)}/{len(results)} passed")

# Mini benchmark
print("\n" + "="*55)
print("  Quick Performance Benchmark (1 KB data)")
print("="*55)
for algo in ["Triple DES", "AES", "RSA", "ECC", "ElGamal"]:
    try:
        r = benchmark_algorithm(algo, [1])
        m = r["1KB"]
        print(f"  {algo:<12}  Enc: {m['encrypt_ms']:7.2f} ms  Dec: {m['decrypt_ms']:7.2f} ms")
    except Exception as e:
        print(f"  {algo:<12}  Error: {e}")

print("="*55 + "\n")
