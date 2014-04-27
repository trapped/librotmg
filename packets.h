#ifndef rotmg_packets_h

#define rotmg_packets_h

#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "rotmg.h"

//packet structs

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

typedef struct rotmg_packet_failure {
	short          error_message_length;
	unsigned char* error_message;
} rotmg_packet_failure;

//struct to data and vice versa functions

rotmg_packet* rotmg_strtopkt_failure (rotmg_packet_failure* str);
rotmg_packet* rotmg_strtopkt_hello   (rotmg_packet_hello* str);

#endif