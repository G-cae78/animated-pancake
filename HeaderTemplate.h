/* Create a header file for each source code file using the same name, but with a "*.h" extension. */
/* Keep it in the same folder as the source code file, and include it via #include "file.h" */

#ifndef HEADERTEMPLATE_H /* This symbolic name is unique and should match the file name. */
#define HEADERTEMPLATE_H /* This expression makes sure that this header file is only included once. */

/* Add all your function prototypes, macros, #defines, etc. below. */
//Function to print useful error messages when encryption or decryption fails
void handleErrors(void);

//Function prototypes for encryption and decryption functions (used for both OpenSSL.c and TripleDES.c)
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, const EVP_CIPHER *cipher);
int decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, int ciphertext_len, unsigned char *decryptedtext, const EVP_CIPHER *cipher);

#endif