#include <stdio.h>
#include <string.h>

// Simple crypto functions for testing
void xor_encrypt(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

unsigned int simple_hash(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

void aes_like_function(unsigned char *block) {
    // Simulated AES-like operations
    for (int i = 0; i < 16; i++) {
        block[i] = (block[i] << 1) | (block[i] >> 7);
    }
}

int main() {
    unsigned char data[] = "Hello, Crypto!";
    printf("Original: %s\n", data);
    
    xor_encrypt(data, strlen((char*)data), 0x42);
    printf("Encrypted: ");
    for (int i = 0; i < strlen((char*)data); i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
    
    unsigned int hash = simple_hash("test");
    printf("Hash: %u\n", hash);
    
    return 0;
}
