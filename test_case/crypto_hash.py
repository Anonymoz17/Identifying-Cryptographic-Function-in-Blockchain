"""
crypto_hash.py - Python crypto demonstration for static analysis testing

This script demonstrates cryptographic operations in Python.
Static analysis will detect these patterns.
Dynamic analysis won't run this (it's source code).

Run with: python crypto_hash.py
"""

import hashlib
import hmac
import secrets
from typing import bytes

def demonstrate_hashing():
    """Show various hashing algorithms that static analysis can detect."""
    print("[1] Hashing Demonstrations")
    print("-" * 40)
    
    # SHA256 - static analysis will flag this
    data = b"Hello, Cryptographic World!"
    
    # Using hashlib.sha256
    sha256_hash = hashlib.sha256(data).digest()
    print(f"SHA256 hash generated: {sha256_hash.hex()[:32]}...")
    
    # Using hashlib.md5
    md5_hash = hashlib.md5(data).digest()
    print(f"MD5 hash generated: {md5_hash.hex()}")
    
    # Using hashlib.sha512
    sha512_hash = hashlib.sha512(data).digest()
    print(f"SHA512 hash generated: {sha512_hash.hex()[:32]}...")
    
    # Using hashlib.sha1 (deprecated but common)
    sha1_hash = hashlib.sha1(data).digest()
    print(f"SHA1 hash generated: {sha1_hash.hex()}")
    
    return sha256_hash

def demonstrate_hmac():
    """Demonstrate HMAC (hash-based message authentication code)."""
    print("\n[2] HMAC Demonstrations")
    print("-" * 40)
    
    key = b"secret_key_12345"
    message = b"message to authenticate"
    
    # HMAC-SHA256
    hmac_result = hmac.new(key, message, hashlib.sha256).digest()
    print(f"HMAC-SHA256 generated: {hmac_result.hex()[:32]}...")
    
    # HMAC-SHA512
    hmac_sha512 = hmac.new(key, message, hashlib.sha512).digest()
    print(f"HMAC-SHA512 generated: {hmac_sha512.hex()[:32]}...")
    
    return hmac_result

def demonstrate_random_generation():
    """Demonstrate cryptographic random number generation."""
    print("\n[3] Random Generation")
    print("-" * 40)
    
    # Generate random bytes (uses system entropy)
    random_bytes = secrets.token_bytes(32)
    print(f"Random bytes generated: {random_bytes.hex()[:32]}...")
    
    # Generate random hex string
    random_hex = secrets.token_hex(16)
    print(f"Random hex generated: {random_hex}")
    
    # Generate random URL-safe string
    random_url = secrets.token_urlsafe(32)
    print(f"Random URL-safe generated: {random_url}")
    
    return random_bytes

def main():
    """Main function demonstrating various crypto operations."""
    print("=" * 40)
    print("Crypto Hash Module - Static Analysis Test")
    print("=" * 40)
    print()
    
    try:
        # Run demonstrations
        hash_result = demonstrate_hashing()
        hmac_result = demonstrate_hmac()
        random_result = demonstrate_random_generation()
        
        print("\n" + "=" * 40)
        print("Summary")
        print("=" * 40)
        print("✓ Multiple hashing algorithms detected")
        print("✓ HMAC operations detected")
        print("✓ Random generation detected")
        print("\nStatic analysis should flag all these crypto operations!")
        print("Dynamic analysis will NOT run (Python source code)")
        
    except Exception as e:
        print(f"Error during demonstrations: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
