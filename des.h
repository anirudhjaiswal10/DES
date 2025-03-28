#ifndef DES_H
#define DES_H

#include <stdint.h>
#include <stdlib.h>

// DES Block and Key Sizes
#define DES_BLOCK_SIZE 8  // 64-bit block
#define DES_KEY_SIZE 8     // 64-bit key

// DES Operation Modes
#define DES_ENCRYPT 1
#define DES_DECRYPT 0

// Structure for DES round keys (each subkey is 48 bits)
typedef struct {
    uint64_t subkeys[16];  // 16 subkeys, each derived from the main key
} DES_RoundKeys;

// ================================
//      Key Schedule Functions
// ================================

/**
 * @brief Applies a permutation table to an input value.
 * @param output Pointer to store the result.
 * @param input Input value to permute.
 * @param table Permutation table.
 * @param n Number of elements in the table.
 */
void des_apply_permutation(uint64_t *output, uint64_t input, const uint8_t *table, int n);

/**
 * @brief Generates 16 round subkeys from the given key.
 * @param key 64-bit input key.
 * @param round_keys Pointer to store generated round keys.
 */
void des_generate_round_keys(uint64_t key, uint64_t *round_keys);

/**
 * @brief Feistel function (expands and substitutes the right half of the block).
 * @param right 32-bit right half of the data.
 * @param subkey 48-bit round subkey.
 * @param output Pointer to store the result.
 */
void des_feistel_function(uint32_t right, uint64_t subkey, uint32_t *output);

// ================================
//      Block Encryption/Decryption
// ================================

/**
 * @brief Encrypts a single 64-bit block using DES.
 * @param input Pointer to 8-byte plaintext block.
 * @param output Pointer to store 8-byte ciphertext block.
 * @param key 64-bit encryption key.
 */
void des_encrypt_block(const uint8_t *input, uint8_t *output, uint64_t key);

/**
 * @brief Decrypts a single 64-bit block using DES.
 * @param input Pointer to 8-byte ciphertext block.
 * @param output Pointer to store 8-byte plaintext block.
 * @param key 64-bit decryption key.
 */
void des_decrypt_block(const uint8_t *input, uint8_t *output, uint64_t key);

// ================================
//      CBC Mode Encryption/Decryption
// ================================

/**
 * @brief Encrypts data using DES in CBC mode.
 * @param data Pointer to the data buffer (must be a multiple of 8 bytes).
 * @param length Data length (should be a multiple of 8).
 * @param key 64-bit encryption key.
 * @param iv 8-byte initialization vector.
 */
void des_cbc_encrypt(uint8_t *data, size_t length, uint64_t key, uint8_t iv[8]);

/**
 * @brief Decrypts data using DES in CBC mode.
 * @param data Pointer to the ciphertext buffer.
 * @param length Data length (should be a multiple of 8).
 * @param key 64-bit decryption key.
 * @param iv 8-byte initialization vector.
 */
void des_cbc_decrypt(uint8_t *data, size_t length, uint64_t key, uint8_t iv[8]);

// ================================
//      Utility Functions
// ================================

/**
 * @brief Converts a 64-bit value to big-endian byte array.
 * @param value 64-bit integer.
 * @param bytes Pointer to an 8-byte array.
 */
void des_uint64_to_be_bytes(uint64_t value, uint8_t *bytes);

/**
 * @brief Converts an 8-byte big-endian array to a 64-bit integer.
 * @param bytes Pointer to an 8-byte array.
 * @return Converted 64-bit integer.
 */
uint64_t des_be_bytes_to_uint64(const uint8_t *bytes);

/**
 * @brief Retrieves round keys for debugging purposes.
 * @param key 64-bit encryption key.
 * @param round_keys Pointer to store generated round keys.
 */


// ================================
//      DES Constants (Extern)
// ================================

// Permutation tables
extern const uint8_t DES_INITIAL_KEY_PERMUTATION[];
extern const uint8_t DES_INITIAL_MESSAGE_PERMUTATION[];
extern const uint8_t DES_KEY_SHIFT_SIZES[];
extern const uint8_t DES_SUB_KEY_PERMUTATION[];
extern const uint8_t DES_MESSAGE_EXPANSION[];
extern const uint8_t DES_RIGHT_SUB_MESSAGE_PERMUTATION[];
extern const uint8_t DES_FINAL_MESSAGE_PERMUTATION[];

// S-Boxes (8 substitution tables)
extern const uint32_t DES_SBOX1[];
extern const uint32_t DES_SBOX2[];
extern const uint32_t DES_SBOX3[];
extern const uint32_t DES_SBOX4[];
extern const uint32_t DES_SBOX5[];
extern const uint32_t DES_SBOX6[];
extern const uint32_t DES_SBOX7[];
extern const uint32_t DES_SBOX8[];

#endif // DES_H
