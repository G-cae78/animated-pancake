#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include "HeaderTemplate.h"
#include <stdio.h>

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, const EVP_CIPHER *cipher) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Pass iv here — OpenSSL ignores it automatically for ECB
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, int ciphertext_len, unsigned char *decryptedtext, const EVP_CIPHER *cipher) {
    EVP_CIPHER_CTX *ctx;
    int len, decryptedtext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Pass iv here — OpenSSL ignores it automatically for ECB
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
        handleErrors();
    decryptedtext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) handleErrors();
    decryptedtext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return decryptedtext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
