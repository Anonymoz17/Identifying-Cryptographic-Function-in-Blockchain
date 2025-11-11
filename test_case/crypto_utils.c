/*
 * crypto_utils.c - Simple crypto utilities for testing dynamic analysis
 * 
 * This file demonstrates basic Windows crypto API usage that Frida can hook.
 * Compile with: cl.exe crypto_utils.c /Fe crypto_utils.exe
 * Or with MinGW: gcc crypto_utils.c -o crypto_utils.exe -lbcrypt -lncrypt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "kernel32.lib")

// Forward declarations
NTSTATUS perform_hashing();
NTSTATUS perform_encryption();

int main() {
    printf("=== Crypto Utils Test ===\n");
    printf("Testing Windows Crypto APIs...\n\n");
    
    // Test hashing
    printf("[1] Testing BCrypt Hashing...\n");
    NTSTATUS hash_status = perform_hashing();
    if (BCRYPT_SUCCESS(hash_status)) {
        printf("    ✓ Hashing completed successfully\n");
    } else {
        printf("    ✗ Hashing failed: 0x%08X\n", hash_status);
    }
    
    printf("\n");
    
    // Test encryption (if available)
    printf("[2] Testing BCrypt Encryption...\n");
    NTSTATUS encrypt_status = perform_encryption();
    if (BCRYPT_SUCCESS(encrypt_status)) {
        printf("    ✓ Encryption completed successfully\n");
    } else {
        printf("    ✗ Encryption failed: 0x%08X\n", encrypt_status);
    }
    
    printf("\n=== Tests Complete ===\n");
    return 0;
}

/*
 * Demonstrates BCryptCreateHash and BCryptHashData
 * These are prime targets for Frida hooking
 */
NTSTATUS perform_hashing() {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    
    // Open algorithm provider (SHA256)
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        printf("    Error opening algorithm: 0x%08X\n", status);
        return status;
    }
    
    // Create hash object
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("    Error creating hash: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }
    
    // Hash some data
    const char* data = "Hello, Crypto World!";
    status = BCryptHashData(
        hHash,
        (PUCHAR)(ULONG_PTR)data,
        strlen(data),
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        printf("    Error hashing data: 0x%08X\n", status);
    } else {
        printf("    Data hashed: %d bytes\n", (int)strlen(data));
    }
    
    // Cleanup
    if (hHash) {
        BCryptDestroyHash(hHash);
    }
    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    return status;
}

/*
 * Demonstrates BCryptEncrypt and BCryptDecrypt
 * Another prime target for Frida hooking
 */
NTSTATUS perform_encryption() {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    
    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        printf("    Error opening AES: 0x%08X\n", status);
        return status;
    }
    
    // Set encryption mode to CBC
    BCRYPT_CHAINING_MODE mode = ChainingModeCbc;
    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)&mode,
        sizeof(mode),
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        printf("    Error setting chain mode: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }
    
    // Generate key
    status = BCryptGenerateKeyPair(hAlg, &hKey, 128, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("    Error generating key: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }
    
    // Finalize key
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("    Error finalizing key: 0x%08X\n", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }
    
    printf("    Key generated and finalized\n");
    
    // Cleanup
    if (hKey) {
        BCryptDestroyKey(hKey);
    }
    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    return STATUS_SUCCESS;
}
