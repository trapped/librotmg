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

unsigned char* pub_encrypt      (unsigned char* data, int data_length, rsa_util* key);
unsigned char* priv_encrypt     (unsigned char* data, int data_length, rsa_util* key);
unsigned char* pub_decrypt      (unsigned char* data, int data_length, rsa_util* key);
unsigned char* priv_decrypt     (unsigned char* data, int data_length, rsa_util* key);
void           print_last_error (void);

rsa_util*
rsa_make(unsigned char* privkey, int privkey_length, unsigned char* pubkey, int pubkey_length)
{
	rsa_util* res = NULL;
	if (privkey_length != 0 && privkey != NULL)
	{
		if (res == NULL)
		{
			res = malloc(sizeof(rsa_util));
		}
		res->priv_key = privkey;
		RSA* rsa = RSA_new();
		FILE* keyfile = fmemopen(privkey, sizeof(char) * privkey_length, "r");
		rsa = PEM_read_RSAPrivateKey(keyfile, &rsa, NULL, NULL);
		res->priv_key_rsa = rsa;
		fclose(keyfile);
	}
	if (pubkey_length != 0 && pubkey != NULL)
	{
		if (res == NULL)
		{
			res = malloc(sizeof(rsa_util));
		}
		res->pub_key = pubkey;
		RSA* rsa = RSA_new();
		FILE* keyfile = fmemopen(pubkey, sizeof(char) * pubkey_length, "r");
		rsa = PEM_read_RSA_PUBKEY(keyfile, &rsa, NULL, NULL);
		res->pub_key_rsa = rsa;
		fclose(keyfile);
	}
	return res;
}

unsigned char*
pub_encrypt(unsigned char* data, int data_length, rsa_util* key)
{
	char* encrypted = malloc(sizeof(char) * RSA_size(key->pub_key_rsa));
	int result = RSA_public_encrypt(data_length, data, encrypted, key->pub_key_rsa, RSA_PKCS1_PADDING);
	if (result == -1)
	{
		free(encrypted);
		return NULL;
	}
	else
	{
		char* enc = malloc(sizeof(char) * result);
		memcpy(enc, encrypted, result);
		free(encrypted);
		return enc;
	}
}

unsigned char*
priv_encrypt(unsigned char* data, int data_length, rsa_util* key)
{
	char* encrypted = malloc(sizeof(char) * RSA_size(key->priv_key_rsa));
	int result = RSA_private_encrypt(data_length, data, encrypted, key->priv_key_rsa, RSA_PKCS1_PADDING);
	if (result == -1)
	{
		free(encrypted);
		return NULL;
	}
	else
	{
		char* enc = malloc(sizeof(char) * result);
		memcpy(enc, encrypted, result);
		free(encrypted);
		return enc;
	}
}

unsigned char*
pub_decrypt(unsigned char* data, int data_length, rsa_util* key)
{
	char* decrypted = malloc(sizeof(char) * RSA_size(key->pub_key_rsa));
	int result = RSA_public_decrypt(data_length, data, decrypted, key->pub_key_rsa, RSA_PKCS1_PADDING);
	if (result == -1)
	{
		free(decrypted);
		return NULL;
	}
	else
	{
		char* dec = malloc(sizeof(char) * result);
		memcpy(dec, decrypted, result);
		free(decrypted);
		return dec;
	}
}

unsigned char*
priv_decrypt(unsigned char* data, int data_length, rsa_util* key)
{
	char* decrypted = malloc(sizeof(char) * RSA_size(key->priv_key_rsa));
	int result = RSA_private_decrypt(data_length, data, decrypted, key->priv_key_rsa, RSA_PKCS1_PADDING);
	if (result == -1)
	{
		free(decrypted);
		return NULL;
	}
	else
	{
		char* dec = malloc(sizeof(char) * result);
		memcpy(dec, decrypted, result);
		free(decrypted);
		return dec;
	}
}

void print_last_error()
{
	char* err = malloc(sizeof(char) * 130);
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("rsa error: %s\n", err);
	free(err);
}