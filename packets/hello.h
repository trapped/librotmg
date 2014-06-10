#ifndef rotmg_hello_h

#define rotmg_hello_h

#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../rotmg.h"
#include "../packet_ids.h"
#include "../rsa.h"

typedef struct rotmg_packet_hello {
	short          build_version_length;
	unsigned char* build_version;
	long           game_id;
	short          guid_length;
	unsigned char* guid;
	short          password_length;
	unsigned char* password;
	short          secret_length;
	unsigned char* secret;
	long           key_time;
	short          key_length;
	unsigned char* key;
	short          __Rw_length;
	unsigned char* __Rw;
	short          __06U_length;
	unsigned char* __06U;
	short          __LK_length;
	unsigned char* __LK;
	short          playplatform_length;
	unsigned char* playplatform;
} rotmg_packet_hello;

rotmg_packet* rotmg_strtopkt_hello (rotmg_packet_hello* str, rsa_util* rsa);

#endif
