/*
 * file_utils.c - Non-crypto file handling for testing
 * 
 * This demonstrates typical file operations WITHOUT crypto.
 * Use this to verify that dynamic analysis correctly ignores non-crypto files.
 * 
 * Compile with: cl.exe file_utils.c /Fe file_utils.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int main() {
    printf("=== File Utils Test ===\n");
    printf("Testing standard file operations...\n\n");
    
    // Create a test file
    const char* filename = "test_output.txt";
    FILE* file = fopen(filename, "w");
    
    if (!file) {
        printf("Error: Cannot create file %s\n", filename);
        return 1;
    }
    
    printf("[1] Writing data...\n");
    fprintf(file, "This is a test file\n");
    fprintf(file, "It contains no cryptographic operations\n");
    fprintf(file, "Dynamic analysis should NOT detect any crypto calls\n");
    fclose(file);
    printf("    ✓ File written: %s\n", filename);
    
    // Read it back
    printf("\n[2] Reading file...\n");
    file = fopen(filename, "r");
    if (file) {
        char buffer[256];
        int line_count = 0;
        while (fgets(buffer, sizeof(buffer), file)) {
            line_count++;
            printf("    Line %d: %s", line_count, buffer);
        }
        fclose(file);
        printf("    ✓ File read: %d lines\n", line_count);
    }
    
    // Perform some string operations
    printf("\n[3] String operations...\n");
    char data[] = "Hello, World!";
    printf("    Input: %s\n", data);
    printf("    Length: %zu bytes\n", strlen(data));
    
    char upper[256];
    strcpy_s(upper, sizeof(upper), data);
    for (int i = 0; upper[i]; i++) {
        if (upper[i] >= 'a' && upper[i] <= 'z') {
            upper[i] = upper[i] - 32;
        }
    }
    printf("    Upper: %s\n", upper);
    
    // Memory operations
    printf("\n[4] Memory operations...\n");
    DWORD buffer_size = 1024;
    void* buffer = malloc(buffer_size);
    if (buffer) {
        memset(buffer, 0, buffer_size);
        printf("    ✓ Allocated %lu bytes\n", buffer_size);
        memcpy(buffer, data, strlen(data));
        printf("    ✓ Copied data\n");
        free(buffer);
        printf("    ✓ Memory freed\n");
    }
    
    // Clean up test file
    remove(filename);
    printf("\n[5] Cleanup\n");
    printf("    ✓ Test file deleted\n");
    
    printf("\n=== Test Complete (NO CRYPTO DETECTED) ===\n");
    return 0;
}
