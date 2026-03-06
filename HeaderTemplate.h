/* Create a header file for each source code file using the same name, but with a "*.h" extension. */
/* Keep it in the same folder as the source code file, and include it via #include "file.h" */

#ifndef FILENAME /* This symbolic name is unique and should match the file name. */
#define FILENAME /* This expression makes sure that this header file is only included once. */

/* Add all your function prototypes, macros, #defines, etc. below. */
void handleErrors(void);
int encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, const EVP_CIPHER *cipher);
int decrypt(unsigned char *ciphertext, unsigned char *key, int ciphertext_len, unsigned char *decryptedtext, const EVP_CIPHER *cipher);
void print_cpu_time(char* label);
#endif