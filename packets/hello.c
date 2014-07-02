#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "../utils.h"
#include "../rotmg.h"
#include "../packet_ids.h"
#include "../rsa.h"

typedef struct rotmg_packet_hello {
	short          build_version_length;
	unsigned char* build_version;
	long           game_id;
	short          guid_length;
	unsigned char* guid; //rsa
	long		   randomint1;
	short          password_length;
	unsigned char* password; //rsa
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

rotmg_packet*
rotmg_strtopkt_hello (rotmg_packet_hello* str, rsa_util* rsa)
{
	//rsa encrypted data length (guid and password length)
	short encrypted_length = (short)get_modulus_bytes(rsa->pub_key_rsa);
	//build version length
	unsigned char* temp_build_version_length = stoc(str->build_version_length);
	unsigned char* build_version_length = reverse_endian(2, temp_build_version_length);
	free(temp_build_version_length);
	//game id
	unsigned char* temp_game_id = ltoc(str->game_id);
	unsigned char* game_id = reverse_endian(4, temp_game_id);
	free(temp_game_id);
	//encrypted guid to base64
	unsigned char* temp_encrypted_guid = (unsigned char*)pub_encrypt(str->guid, str->guid_length, rsa);
	unsigned char* encrypted_guid = (unsigned char*)b64_enc((int)encrypted_length, temp_encrypted_guid);
	free(temp_encrypted_guid);
	//encrypted guid length
	unsigned char* temp_encrypted_guid_length = stoc(strlen((char*)encrypted_guid));
	unsigned char* encrypted_guid_length = reverse_endian(2, temp_encrypted_guid_length);
	free(temp_encrypted_guid_length);
	//randomint1
	unsigned char* temp_randomint1 = ltoc(str->randomint1);
	unsigned char* randomint1 = reverse_endian(4, temp_randomint1);
	free(temp_randomint1);
	//encrypted password to base64
	unsigned char* temp_encrypted_password = (unsigned char*)pub_encrypt(str->password, str->password_length, rsa);
	unsigned char* encrypted_password = (unsigned char*)b64_enc((int)encrypted_length, temp_encrypted_password);
	free(temp_encrypted_password);
	//encrypted password length
	unsigned char* temp_encrypted_password_length = stoc(strlen((char*)encrypted_password));
	unsigned char* encrypted_password_length = reverse_endian(2, temp_encrypted_password_length);
	free(temp_encrypted_password_length);
	//randomint2
	unsigned char* temp_randomint2 = ltoc(str->randomint2);
	unsigned char* randomint2 = reverse_endian(4, temp_randomint2);
	free(temp_randomint2);
	//secret length
	unsigned char* temp_secret_length = stoc(str->secret_length);
	unsigned char* secret_length = reverse_endian(2, temp_secret_length);
	//secret has no processing
	//key time
	unsigned char* temp_key_time = ltoc(str->key_time);
	unsigned char* key_time = reverse_endian(4, temp_key_time);
	free(temp_key_time);
	//key length
	unsigned char* temp_key_length = stoc(str->key_length);
	unsigned char* key_length = reverse_endian(2, temp_key_length);
	free(temp_key_length);
	//map info length
	unsigned char* temp_mapinfo_length = ltoc(str->mapinfo_length);
	unsigned char* mapinfo_length = reverse_endian(4, temp_mapinfo_length);
	free(temp_mapinfo_length);
	//obf1 length
	unsigned char* temp_obf1_length = stoc(str->obf1_length);
	unsigned char* obf1_length = reverse_endian(2, temp_obf1_length);
	free(temp_obf1_length);
	//obf2 length
	unsigned char* temp_obf2_length = stoc(str->obf2_length);
	unsigned char* obf2_length = reverse_endian(2, temp_obf2_length);
	free(temp_obf2_length);
	//obf3 length
	unsigned char* temp_obf3_length = stoc(str->obf3_length);
	unsigned char* obf3_length = reverse_endian(2, temp_obf3_length);
	free(temp_obf3_length);
	//bf4 length
	unsigned char* temp_obf4_length = stoc(str->obf4_length);
	unsigned char* obf4_length = reverse_endian(2, temp_obf4_length);
	free(temp_obf4_length);
	//obf5 length
	unsigned char* temp_obf5_length = stoc(str->obf5_length);
	unsigned char* obf5_length = reverse_endian(2, temp_obf5_length);
	free(temp_obf5_length);

	rotmg_packet* pkt = calloc(1, sizeof(rotmg_packet));
	if(!pkt) {
		puts("couldn't allocate memory for an hello packet");
		return NULL;
	}

	long size = (sizeof(short)*10)+(sizeof(long)*5)+
				(sizeof(char)*str->build_version_length)+
				(sizeof(char)*strlen((char*)encrypted_guid))+
				(sizeof(char)*strlen((char*)encrypted_password))+
				(sizeof(char)*str->secret_length)+
				(sizeof(char)*str->key_length)+
				(sizeof(char)*str->mapinfo_length)+
				(sizeof(char)*str->obf1_length)+
				(sizeof(char)*str->obf2_length)+
				(sizeof(char)*str->obf3_length)+
				(sizeof(char)*str->obf4_length)+
				(sizeof(char)*str->obf5_length);

	pkt->payload = calloc(1, size);
	if(!pkt->payload) {
		puts("couldn't allocate memory for an hello packet's payload");
		return NULL;
	}
	pkt->type = HELLO_2210;
	pkt->length = size;

	int position = 0;
	//build_version_length
	memcpy(&(pkt->payload[position]), build_version_length, 2);
	free(build_version_length);
	position += 2;
	//build_version
	memcpy(&(pkt->payload[position]), str->build_version, str->build_version_length);
	position += str->build_version_length;
	//game_id
	memcpy(&(pkt->payload[position]), game_id, 4);
	free(game_id);
	position += 4;
	//guid_length
	memcpy(&(pkt->payload[position]), encrypted_guid_length, 2);
	free(encrypted_guid_length);
	position += 2;
	//guid
	memcpy(&(pkt->payload[position]), encrypted_guid, strlen((char*)encrypted_guid));
	position += strlen((char*)encrypted_guid);
	free(encrypted_guid);
	//randomint1
	memcpy(&(pkt->payload[position]), randomint1, 4);
	free(randomint1);
	position += 4;
	//password_length
	memcpy(&(pkt->payload[position]), encrypted_password_length, 2);
	free(encrypted_password_length);
	position += 2;
	//password
	memcpy(&(pkt->payload[position]), encrypted_password, strlen((char*)encrypted_password));
	position += strlen((char*)encrypted_password);
	free(encrypted_password);
	//randomint2
	memcpy(&(pkt->payload[position]), randomint2, 4);
	free(randomint2);
	position += 4;
	//secret_length
	memcpy(&(pkt->payload[position]), secret_length, 2);
	free(secret_length);
	position += 2;
	//secret
	memcpy(&(pkt->payload[position]), str->secret, str->secret_length);
	position += str->secret_length;
	//key_time
	memcpy(&(pkt->payload[position]), key_time, 4);
	free(key_time);
	position += 4;
	//key_length
	memcpy(&(pkt->payload[position]), key_length, 2);
	free(key_length);
	position += 2;
	//key
	memcpy(&(pkt->payload[position]), str->key, str->key_length);
	position += str->key_length;
	//mapinfo_length
	memcpy(&(pkt->payload[position]), mapinfo_length, 4);
	free(mapinfo_length);
	position += 4;
	//mapinfo
	memcpy(&(pkt->payload[position]), str->mapinfo, str->mapinfo_length);
	position += str->mapinfo_length;
	//obf1_length
	memcpy(&(pkt->payload[position]), obf1_length, 2);
	free(obf1_length);
	position += 2;
	//obf1
	memcpy(&(pkt->payload[position]), str->obf1, str->obf1_length);
	position += str->obf1_length;
	//obf2_length
	memcpy(&(pkt->payload[position]), obf2_length, 2);
	free(obf2_length);
	position += 2;
	//obf2
	memcpy(&(pkt->payload[position]), str->obf2, str->obf2_length);
	position += str->obf2_length;
	//obf3_length
	memcpy(&(pkt->payload[position]), obf3_length, 2);
	free(obf3_length);
	position += 2;
	//obf3
	memcpy(&(pkt->payload[position]), str->obf3, str->obf3_length);
	position += str->obf3_length;
	//obf4_length
	memcpy(&(pkt->payload[position]), obf4_length, 2);
	free(obf4_length);
	position += 2;
	//obf4
	memcpy(&(pkt->payload[position]), str->obf4, str->obf4_length);
	position += str->obf4_length;
	//obf5_length
	memcpy(&(pkt->payload[position]), obf5_length, 2);
	free(obf5_length);
	position += 2;
	//obf5
	memcpy(&(pkt->payload[position]), str->obf5, str->obf5_length);
	position += str->obf5_length;

	return pkt;
}
