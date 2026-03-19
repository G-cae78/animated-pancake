#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include "HeaderTemplate.h"
#include <stdio.h>
#include <stdlib.h>

struct timespec start, end;

/*  Run with  cd "cd "/Users/"Username"/Documents/Fourth Year/Computer and Network Security/Assignment 2" && \
    gcc -o TripleDES TripleDES.c Functions.c -lcrypto 2>&1 && ./TripleDES*/

// struct OpenSSLSettings
// {
//     const EVP_CIPHER *cipher;
//     const char *name;
// };

int main (void)
{
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Triple-DES uses a 24-byte (192-bit) key */
    unsigned char key3des[24] = "012345678901234567890123";

    /* Data sizes: 100 MB and 1000 MB */
    size_t data_sizes[] = { 100UL * 1024 * 1024, 1000UL * 1024 * 1024 };

    /* ECB and CBC modes for 3DES Cipher */
    const EVP_CIPHER *cipher_table[2] = {
        EVP_des_ede3_ecb(), EVP_des_ede3_cbc()
    };

    double elapsed;

    /* Outer loop: data sizes */
    for (int d = 0; d < 2; d++) {
        size_t data_len = data_sizes[d];
        printf("\n==================================================\n");
        printf("Data size: %zu MB\n", data_len / (1024 * 1024));
        printf("==================================================\n");

        /* Allocate plaintext and output buffers once per data size */
        unsigned char *plaintext     = malloc(data_len);
        unsigned char *ciphertext    = malloc(data_len + EVP_MAX_BLOCK_LENGTH);
        unsigned char *decryptedtext = malloc(data_len + EVP_MAX_BLOCK_LENGTH);

        if (!plaintext || !ciphertext || !decryptedtext) {
            fprintf(stderr, "Memory allocation failed\n"); //errormessage if memory allocation fails
            return 1;
        }

        /* Fill plaintext with repeated pattern */
        memset(plaintext, 0x41, data_len);    // Fill memory with 'A's' (0x41)

        printf("\n  Key size: 192-bit (Triple-DES)\n");

        /* Loop: ECB and CBC */
        for (int i = 0; i < 2; i++) {
            const EVP_CIPHER *cipher = cipher_table[i];

            printf("  --------------------------------------------------\n");
            printf("  Cipher: %s\n", EVP_CIPHER_name(cipher));

            /* Encryption */
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
            int ciphertext_len = encrypt(plaintext, (int)data_len, key3des, ciphertext, cipher);
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
            elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("  Encrypt CPU time: %.6f s\n", elapsed);

            /* Decryption */
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
            int decryptedtext_len = decrypt(ciphertext, key3des, ciphertext_len, decryptedtext, cipher);
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
            elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("  Decrypt CPU time: %.6f s\n", elapsed);
            printf("  Decrypted length: %d bytes\n", decryptedtext_len);

            /* Verify correctness */
            if (decryptedtext_len != (int)data_len || memcmp(plaintext, decryptedtext, data_len) != 0) {
                fprintf(stderr, "Decryption failed: output does not match original plaintext\n");
            }
        }

        free(plaintext);
        free(ciphertext);
        free(decryptedtext);
    }

    /* Clean up once at the end */
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}