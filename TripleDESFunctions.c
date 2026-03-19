#include <openssl/err.h>
#include <openssl/des.h>
#include "HeaderTemplate.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void encrypt_TRIPLEDES(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, const EVP_CIPHER *cipher) {
    
    
}
void decrypt_TRIPLEDES(unsigned char *ciphertext, unsigned char *key, int ciphertext_len, unsigned char *decryptedtext, const EVP_CIPHER *cipher) {


}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}