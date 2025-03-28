#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "des.h"

void print_hex(FILE *fp, const char *label, const uint8_t *data, size_t length) {
    fprintf(fp, "%s: ", label);
    for (size_t i = 0; i < length; i++) {
        fprintf(fp, "%02X ", data[i]);
    }
    fprintf(fp, "\n");
}

void generate_random_iv(uint8_t iv[8]) {
    for (int i = 0; i < 8; i++) {
        iv[i] = rand() & 0xFF;
    }
}

void test_cbc_mode(size_t data_size, uint64_t key, FILE *fp, uint8_t *input_text) {
    fprintf(fp, "\n=== Testing CBC Mode for %zu Bytes ===\n", data_size);

    for (int i = 0; i < 5; i++) {
        uint8_t *data = (uint8_t *)malloc(data_size);
        uint8_t *original_data = (uint8_t *)malloc(data_size);
        uint8_t iv[8], decrypt_iv[8];

        if (!data || !original_data) {
            fprintf(stderr, "Memory allocation failed!\n");
            exit(1);
        }

        if (data_size <= 16) {
            memcpy(data, input_text, data_size);
        } else {
            for (size_t j = 0; j < data_size; j++) {
                data[j] = (uint8_t)(rand() % 256);
            }
        }
        memcpy(original_data, data, data_size);

        generate_random_iv(iv);
        memcpy(decrypt_iv, iv, 8);

        print_hex(fp, "IV", iv, 8);
        print_hex(fp, "Plaintext", data, data_size > 16 ? 16 : data_size);

        des_cbc_encrypt(data, data_size, key, iv);
        print_hex(fp, "CBC Encrypted", data, data_size > 16 ? 16 : data_size);

        des_cbc_decrypt(data, data_size, key, decrypt_iv);
        print_hex(fp, "CBC Decrypted", data, data_size > 16 ? 16 : data_size);

        if (memcmp(original_data, data, data_size) == 0) {
            fprintf(fp, "Iteration %d: SUCCESS\n", i + 1);
        } else {
            fprintf(fp, "Iteration %d: FAILURE\n", i + 1);
        }

        free(data);
        free(original_data);
    }
}

int main() {
    srand(time(NULL));
    FILE *fp = fopen("output.txt", "w");
    if (!fp) {
        printf("Error opening file!\n");
        return 1;
    }

    uint64_t key = 0x133457799BBCDFF1;
    uint8_t input_text[16];
    
    printf("Enter a plaintext (up to 16 characters): ");
    fgets((char *)input_text, 16, stdin);

    size_t len = strlen((char *)input_text);
    if (len > 0 && input_text[len - 1] == '\n') {
        input_text[len - 1] = '\0';
    }

    test_cbc_mode(8, key, fp, input_text);
    test_cbc_mode(16, key, fp, input_text);
    test_cbc_mode(1024, key, fp, NULL);
    test_cbc_mode(1024 * 1024, key, fp, NULL);

    fclose(fp);
    printf("Encryption/Decryption results saved in output.txt\n");

    return 0;
}
