#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include "HeaderTemplate.h"
#include <stdio.h>


struct timespec start, end;

/*  Run with  cd "/Users/"Username"/Documents/Fourth Year/Computer and Network Security/Assignment 2" && \
    gcc -o OpenSSL OpenSSL.c Functions.c -lcrypto 2>&1 && ./OpenSSL*/ 

    struct OpenSSLSettings
    {
        const EVP_CIPHER *cipher;
    };
    
int main (void)
{
    /* Initialise the OpenSSL library AES, ARIA and CAMELLIA */
    struct OpenSSLSettings settings[] = {{EVP_aes_128_ofb()}, 
                                        {EVP_aria_128_ofb()}, 
                                        {EVP_camellia_128_ofb()}};

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Your code goes here. */

    /* Message to be encrypted */
    unsigned char key[32] = "01234567890123456789012345678901"; 

    unsigned char plaintext[128] = "Hello World!"; //Buffer for the plaintext
    unsigned char ciphertext[128] = {0}; //Buffer for the ciphertext
    unsigned char decryptedtext[128] = {0}; //Buffer for the decrypted text

    int decryptedtext_len, ciphertext_len;
    double elapsed;

    for (int i = 0; i < sizeof(settings) / sizeof(settings[0]); i++) {
        printf("--------------------------------------------------\n");
        printf("Using cipher: %s\n", EVP_CIPHER_name(settings[i].cipher));
        /* Encrypt the plaintext */
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        ciphertext_len = encrypt(plaintext, key, ciphertext, settings[i].cipher);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        printf("Encrypt CPU time: %f s\n", elapsed);
        printf("Ciphertext length is %d:\n", ciphertext_len);
        BIO_dump_fp(stdout, (const unsigned char *)ciphertext, ciphertext_len);

        printf("\n");

        /* Decrypt the ciphertext */
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        decryptedtext_len = decrypt(ciphertext, key, ciphertext_len, decryptedtext, settings[i].cipher);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        printf("Decrypt CPU time: %f s\n", elapsed);
        printf("Decrypted text length is %d:\n", decryptedtext_len);
    
        decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
        printf("Decrypted text is:\n%s\n", decryptedtext);

        /* Clean up */
        EVP_cleanup();
        ERR_free_strings();
    }
    
    /* 
      Console output should be:
      Ciphertext length is 16:
        0000 - 7a ce 0e 4f 0f fe 35 39-ff 1d 7a b1 ac 31 07 8d   z..O..59..z..1..

      Decrypted text length is 12:
      Decrypted text is:
      Hello World!
    */

    return 0;
}
