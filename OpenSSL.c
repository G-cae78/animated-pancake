#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "HeaderTemplate.h"

// Run with  cd "/Users/"Username"/Documents/Fourth Year/Computer and Network Security/Assignment 2" && gcc -o OpenSSL OpenSSL.c -lcrypto 2>&1
int main (void)
{
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
    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, key, ciphertext);
    printf("Ciphertext length is %d:\n", ciphertext_len);
    BIO_dump_fp(stdout, (const unsigned char *)ciphertext, ciphertext_len);

    printf("\n");

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, key, ciphertext_len, decryptedtext);
    printf("Decrypted text length is %d:\n", decryptedtext_len);
   
    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
    printf("Decrypted text is:\n%s\n", decryptedtext);

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    
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

int encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output. */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext)))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at this stage. */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, unsigned char *key, int ciphertext_len, unsigned char *decryptedtext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int decryptedtext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output. */
    if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
        handleErrors();
    decryptedtext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at this stage. */
    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) handleErrors();
    decryptedtext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedtext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}