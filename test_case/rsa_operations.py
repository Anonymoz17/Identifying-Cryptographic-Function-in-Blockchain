"""
rsa_operations.py - RSA asymmetric cryptography

Demonstrates RSA key generation, encryption, and digital signatures.
Static analysis will detect these operations.

Run with: python rsa_operations.py
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def demonstrate_rsa_key_generation():
    """Demonstrate RSA key pair generation."""
    print("[1] RSA Key Generation")
    print("-" * 40)
    
    # Generate private key (expensive operation)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    print("✓ Generated RSA key pair (2048-bit)")
    print(f"  Public exponent: 65537")
    print(f"  Key size: 2048 bits")
    
    return private_key, public_key

def demonstrate_rsa_encryption(public_key):
    """Demonstrate RSA encryption."""
    print("\n[2] RSA Encryption")
    print("-" * 40)
    
    plaintext = b"Secret message"
    
    # Encrypt with public key
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Plaintext: {plaintext.decode()}")
    print(f"Ciphertext (encrypted): {ciphertext.hex()[:32]}...")
    
    return ciphertext

def demonstrate_rsa_decryption(private_key, ciphertext):
    """Demonstrate RSA decryption."""
    print("\n[3] RSA Decryption")
    print("-" * 40)
    
    # Decrypt with private key
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Decrypted: {decrypted.decode()}")

def demonstrate_digital_signatures(private_key, public_key):
    """Demonstrate digital signatures."""
    print("\n[4] Digital Signatures")
    print("-" * 40)
    
    data = b"This document is authentic"
    
    # Sign data with private key
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print(f"Data: {data.decode()}")
    print(f"Signature: {signature.hex()[:32]}...")
    
    # Verify signature with public key
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✓ Signature verified successfully")
    except Exception as e:
        print(f"✗ Signature verification failed: {e}")

def main():
    """Main function."""
    print("=" * 40)
    print("RSA Operations Module")
    print("=" * 40)
    print()
    
    try:
        private_key, public_key = demonstrate_rsa_key_generation()
        ciphertext = demonstrate_rsa_encryption(public_key)
        demonstrate_rsa_decryption(private_key, ciphertext)
        demonstrate_digital_signatures(private_key, public_key)
        
        print("\n" + "=" * 40)
        print("Summary")
        print("=" * 40)
        print("✓ RSA key generation (2048-bit)")
        print("✓ Asymmetric encryption/decryption")
        print("✓ Digital signature generation and verification")
        print("\nStatic analysis will flag all RSA operations!")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
