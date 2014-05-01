#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define KEY_LENGTH  1024
#define PUB_EXP     65537

typedef struct rsa_util {
	RSA*   pri_key_rsa;
	RSA*   pub_key_rsa;
	size_t pri_len;
	size_t pub_len;
	char*  pri_key;
	char*  pub_key;
} rsa_util;

rsa_util*
rsa_make(char* privkey, int privkey_length, char* pubkey, int pubkey_length)
{
	rsa_util* res = NULL;
	if (privkey_length != 0 && privkey != NULL)
	{
		if (res == NULL)
		{
			res = malloc(sizeof(rsa_util));
		}
		res->pri_key = privkey;
		RSA* rsa = RSA_new();
		FILE* keyfile = fmemopen(privkey, sizeof(char) * privkey_length, "r");
		rsa = PEM_read_RSAPrivateKey(keyfile, &rsa, NULL, NULL);
		res->pri_key_rsa = rsa;
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