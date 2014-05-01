#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define KEY_LENGTH  1024
#define PUB_EXP     65537

typedef struct rsa_util {
	RSA*   priv_key_rsa;
	RSA*   pub_key_rsa;
	size_t priv_len;
	size_t pub_len;
	char*  priv_key;
	char*  pub_key;
} rsa_util;

rsa_util*      rsa_make         (unsigned char* privkey, int privkey_length, unsigned char* pubkey, int pubkey_length);

unsigned char* pub_encrypt      (unsigned char* data, int data_length, rsa_util* key);
unsigned char* priv_encrypt     (unsigned char* data, int data_length, rsa_util* key);
unsigned char* pub_decrypt      (unsigned char* data, int data_length, rsa_util* key);
unsigned char* priv_decrypt     (unsigned char* data, int data_length, rsa_util* key);
void           print_last_error (void);