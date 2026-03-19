#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include "HeaderTemplate.h"
#include <stdio.h>

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, const EVP_CIPHER *cipher) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output. */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at this stage. */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, unsigned char *key, int ciphertext_len, unsigned char *decryptedtext, const EVP_CIPHER *cipher) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int decryptedtext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL))
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
void encrypt_TRIPLEDES(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, const EVP_CIPHER *cipher) {
    
    
}
void decrypt_TRIPLEDES(unsigned char *ciphertext, unsigned char *key, int ciphertext_len, unsigned char *decryptedtext, const EVP_CIPHER *cipher) {


}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
