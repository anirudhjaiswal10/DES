#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "des.h"

#ifdef _WIN32
#include <windows.h>
double get_time() {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / freq.QuadPart;
}
#else
#include <sys/time.h>
double get_time() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + (t.tv_nsec / 1e9);
}
#endif

#define ITERATIONS 5
#define UNROLL_FACTOR 8  // Unrolling factor for optimization

void test_encryption_time(size_t data_size, uint64_t key) {
    double total_enc_time = 0, total_dec_time = 0;

    // Memory allocation
    uint8_t *data;
#ifdef _WIN32
    printf("Allocating memory (malloc) for %zu Bytes...\n", data_size);
    fflush(stdout);
    data = (uint8_t *)malloc(data_size);
#else
    printf("Allocating memory (posix_memalign) for %zu Bytes...\n", data_size);
    fflush(stdout);
    if (posix_memalign((void **)&data, 16, data_size) != 0) {
        data = NULL;
    }
#endif

    if (!data) {
        fprintf(stderr, "Memory allocation failed for %zu Bytes!\n", data_size);
        exit(1);
    }
    printf("Memory allocated successfully!\n");
    fflush(stdout);

    uint8_t iv[8], decrypt_iv[8];
    for (int i = 0; i < 8; i++) iv[i] = rand() & 0xFF;

    for (int i = 0; i < ITERATIONS; i++) {
        // Fill random data
        for (size_t j = 0; j < data_size; j += 8) {
            *(uint64_t *)(data + j) = rand();
        }
        memcpy(decrypt_iv, iv, 8);

        // **Unrolled Encryption**
        printf("Encrypting %zu bytes (iteration %d)...\n", data_size, i + 1);
        fflush(stdout);
        double start_enc = get_time();
        for (size_t j = 0; j + (UNROLL_FACTOR * 8) <= data_size; j += (UNROLL_FACTOR * 8)) {
            for (int k = 0; k < UNROLL_FACTOR; k++) {
                des_cbc_encrypt(data + j + (k * 8), 8, key, iv);
            }
        }
        double end_enc = get_time();
        total_enc_time += (end_enc - start_enc);
        printf("Encryption Done!\n");
        fflush(stdout);

        // **Unrolled Decryption**
        printf("Decrypting %zu bytes (iteration %d)...\n", data_size, i + 1);
        fflush(stdout);
        double start_dec = get_time();
        for (size_t j = 0; j + (UNROLL_FACTOR * 8) <= data_size; j += (UNROLL_FACTOR * 8)) {
            for (int k = 0; k < UNROLL_FACTOR; k++) {
                des_cbc_decrypt(data + j + (k * 8), 8, key, decrypt_iv);
            }
        }
        double end_dec = get_time();
        total_dec_time += (end_dec - start_dec);
        printf("Decryption Done!\n");
        fflush(stdout);
    }

    free(data);  // Free allocated memory

    printf("Data Size: %zu Bytes\n", data_size);
    printf("Average Encryption Time: %.9f seconds\n", total_enc_time / ITERATIONS);
    printf("Average Decryption Time: %.9f seconds\n", total_dec_time / ITERATIONS);
    printf("-----------------------------------------\n");
    fflush(stdout);
}

int main() {
    printf("Starting encryption test...\n");
    fflush(stdout);

    srand(time(NULL));
    uint64_t key = 0x133457799BBCDFF1;

    test_encryption_time(8, key);
    test_encryption_time(16, key);
    test_encryption_time(1024, key);
    test_encryption_time(1048576, key);

    printf("Encryption test completed!\n");
    fflush(stdout);
    return 0;
}
