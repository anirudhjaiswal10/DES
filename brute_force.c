/*
 * Brute-Force Attack on DES
 * This program attempts to brute-force the DES encryption key by trying all
 * possible 56-bit keys to find one that correctly decrypts a known ciphertext.
 */

 #include "des.h"
 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 
 #define KNOWN_PLAINTEXT "HELLO123"
 
 void brute_force_des(uint8_t *ciphertext, uint8_t *iv) {
     uint8_t decrypted[8];
     uint64_t key;
     
     printf("Starting brute-force attack...\n");
     
     for (key = 0; key < (1ULL << 56); key++) {
         uint8_t temp_iv[8];
         memcpy(temp_iv, iv, 8);
         
         memcpy(decrypted, ciphertext, 8);
         des_cbc_decrypt(decrypted, 8, key, temp_iv);
         
         if (memcmp(decrypted, KNOWN_PLAINTEXT, 8) == 0) {
             printf("Key found: %016llX\n", key);
             return;
         }
     }
     printf("Key not found (unlikely).\n");
 }
 
 int main() {
     uint8_t iv[8] = {0};
     uint64_t test_key = 0x133457799BBCDFF1;
     uint8_t plaintext[8] = KNOWN_PLAINTEXT;
     uint8_t ciphertext[8];
     
     des_cbc_encrypt(plaintext, 8, test_key, iv);
     
     brute_force_des(ciphertext, iv);
     
     return 0;
 }