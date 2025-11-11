"""
aes_encryption.py - Advanced encryption demonstration

Demonstrates AES encryption/decryption using cryptography library.
Static analysis will detect encryption operations.

Run with: python aes_encryption.py
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import os

def demonstrate_fernet_encryption():
    """Demonstrate symmetric encryption using Fernet."""
    print("[1] Fernet Symmetric Encryption")
    print("-" * 40)
    
    # Generate a key
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # Encrypt data
    plaintext = b"This is sensitive data that needs encryption"
    ciphertext = cipher.encrypt(plaintext)
    
    print(f"Plaintext: {plaintext.decode()}")
    print(f"Encrypted: {ciphertext[:50]}...")
    
    # Decrypt data
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted: {decrypted.decode()}")
    
    return key, ciphertext

def demonstrate_pbkdf2():
    """Demonstrate password-based key derivation."""
    print("\n[2] PBKDF2 Key Derivation")
    print("-" * 40)
    
    password = b"my_secure_password_123"
    salt = os.urandom(16)
    
    # Derive key from password
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    print(f"Password: {password.decode()}")
    print(f"Derived key: {key.hex()[:32]}...")
    print(f"Iterations: 100000")
    
    return key

def demonstrate_hash_operations():
    """Demonstrate various hashing operations."""
    print("\n[3] Cryptography Library Hashing")
    print("-" * 40)
    
    from cryptography.hazmat.primitives import hashes
    
    data = b"data to hash"
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    hash_result = digest.finalize()
    
    print(f"Data: {data.decode()}")
    print(f"SHA256: {hash_result.hex()[:32]}...")

def main():
    """Main function."""
    print("=" * 40)
    print("AES Encryption Module")
    print("=" * 40)
    print()
    
    try:
        demonstrate_fernet_encryption()
        demonstrate_pbkdf2()
        demonstrate_hash_operations()
        
        print("\n" + "=" * 40)
        print("Summary")
        print("=" * 40)
        print("✓ Symmetric encryption (Fernet)")
        print("✓ Key derivation (PBKDF2)")
        print("✓ Hashing (SHA256)")
        print("\nStatic analysis will flag cryptography library usage!")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
