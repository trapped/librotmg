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
	long		   randomint1;
	short          password_length;
	unsigned char* password;
	long		   randomint2;
	short          secret_length;
	unsigned char* secret;
	long           key_time;
	short          key_length;
	unsigned char* key;
	long		   mapinfo_length;
	unsigned char* mapinfo;
	short          obf1_length;
	unsigned char* obf1;
	short          obf2_length;
	unsigned char* obf2;
	short          obf3_length;
	unsigned char* obf3;
	short          obf4_length;
	unsigned char* obf4;
	short		   obf5_length;
	unsigned char* obf5;
} rotmg_packet_hello;

rotmg_packet* rotmg_strtopkt_hello (rotmg_packet_hello* str, rsa_util* rsa);

#endif
