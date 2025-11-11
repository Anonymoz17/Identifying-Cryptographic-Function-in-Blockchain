"""
blockchain_signing.py - Blockchain-style signing and verification

Demonstrates cryptographic operations commonly used in blockchain:
- ECDSA signatures
- Public key generation from private key
- Hash-based identifiers

Static analysis will detect these operations.

Run with: python blockchain_signing.py
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib

def demonstrate_ecdsa_key_generation():
    """Demonstrate ECDSA key generation (used in blockchain)."""
    print("[1] ECDSA Key Generation")
    print("-" * 40)
    
    # Generate ECDSA key pair
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # This curve is similar to Bitcoin's SECP256K1
        default_backend()
    )
    
    public_key = private_key.public_key()
    
    print("✓ Generated ECDSA key pair")
    print(f"  Curve: SECP256R1 (similar to blockchain curves)")
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print(f"  Private key: {private_pem.decode().split(chr(10))[0]}")
    print(f"  Public key: {public_pem.decode().split(chr(10))[0]}")
    
    return private_key, public_key

def demonstrate_ecdsa_signing(private_key):
    """Demonstrate ECDSA signing."""
    print("\n[2] ECDSA Signing")
    print("-" * 40)
    
    message = b"Transaction data to sign"
    
    # Sign message with ECDSA
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    
    print(f"Message: {message.decode()}")
    print(f"Signature: {signature.hex()[:32]}...")
    
    return signature

def demonstrate_ecdsa_verification(public_key, message, signature):
    """Demonstrate ECDSA signature verification."""
    print("\n[3] ECDSA Verification")
    print("-" * 40)
    
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print("✓ Signature verified successfully")
        print("  (Message is authentic and unchanged)")
    except Exception as e:
        print(f"✗ Signature verification failed: {e}")

def demonstrate_transaction_hash():
    """Demonstrate creating transaction hashes (blockchain style)."""
    print("\n[4] Transaction Hash Generation")
    print("-" * 40)
    
    # Simulate transaction data
    transaction = {
        "from": "0xAlice",
        "to": "0xBob",
        "amount": 100,
        "nonce": 1,
        "timestamp": 1699700000
    }
    
    # Create transaction string and hash it
    tx_string = str(sorted(transaction.items()))
    
    # Double SHA256 (blockchain style)
    hash1 = hashlib.sha256(tx_string.encode()).digest()
    hash2 = hashlib.sha256(hash1).digest()
    
    print(f"Transaction: {str(transaction)[:40]}...")
    print(f"Transaction Hash: {hash2.hex()[:16]}...")
    
    return hash2

def main():
    """Main function."""
    print("=" * 40)
    print("Blockchain Signing Module")
    print("=" * 40)
    print()
    
    try:
        private_key, public_key = demonstrate_ecdsa_key_generation()
        message = b"Transaction data to sign"
        signature = demonstrate_ecdsa_signing(private_key)
        demonstrate_ecdsa_verification(public_key, message, signature)
        demonstrate_transaction_hash()
        
        print("\n" + "=" * 40)
        print("Summary")
        print("=" * 40)
        print("✓ ECDSA key generation")
        print("✓ Signing with private key")
        print("✓ Verification with public key")
        print("✓ Transaction hashing (double SHA256)")
        print("\nStatic analysis will flag all these operations!")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
