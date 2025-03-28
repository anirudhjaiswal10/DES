#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "des.h"

#define ITERATIONS 10  // Number of tests for averaging

// Function to calculate entropy
double calculate_entropy(const uint8_t *data, size_t length) {
    int freq[256] = {0};
    
    for (size_t i = 0; i < length; i++) {
        freq[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / length;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Function to encrypt data with DES in CBC mode and calculate entropy
double compute_des_cbc_entropy(size_t data_size, uint64_t key) {
    uint8_t *data = (uint8_t *)malloc(data_size);
    uint8_t iv[8];
    double total_entropy = 0.0;

    if (!data) {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(1);
    }

    for (int iter = 0; iter < ITERATIONS; iter++) {
        // Generate random data for plaintext
        for (size_t i = 0; i < data_size; i++) {
            data[i] = (uint8_t)(rand() % 256);
        }

        // Generate random IV
        for (int i = 0; i < 8; i++) {
            iv[i] = rand() & 0xFF;
        }

        // Encrypt using DES in CBC mode
        des_cbc_encrypt(data, data_size, key, iv);

        // Compute entropy of the ciphertext
        total_entropy += calculate_entropy(data, data_size);
    }

    // Compute and return overall average entropy
    double avg_entropy = total_entropy / ITERATIONS;
    free(data);
    return avg_entropy;
}

int main() {
    srand(time(NULL));
    uint64_t key = 0x133457799BBCDFF1;

    // Data sizes in bytes
    size_t data_sizes[] = {8, 16, 50, 200, 500, 1024, 100 * 1024, 250 * 1024, 500 * 1024, 750 * 1024, 1024 * 1024};
    const char *size_labels[] = {"8B", "16B", "50B", "200B", "500B", "1KB", "100KB", "250KB", "500KB", "750KB", "1MB"};

    // Open the CSV file to write results
    FILE *csv_file = fopen("des_cbc_entropy_results.csv", "w");
    if (!csv_file) {
        fprintf(stderr, "Failed to open CSV file for writing.\n");
        return 1;
    }

    // Write the header row
    fprintf(csv_file, "Data Size (Bytes),Average Entropy (bits/byte)\n");

    // Loop through each data size and compute entropy, then write to CSV
    for (int i = 0; i < sizeof(data_sizes) / sizeof(data_sizes[0]); i++) {
        double avg_entropy = compute_des_cbc_entropy(data_sizes[i], key);
        fprintf(csv_file, "%s,%.6f\n", size_labels[i], avg_entropy);
    }

    // Close the CSV file
    fclose(csv_file);

    printf("Entropy results have been written to des_cbc_entropy_results.csv\n");

    return 0;
}
