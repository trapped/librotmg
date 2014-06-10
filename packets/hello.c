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

rotmg_packet*
rotmg_strtopkt_hello (rotmg_packet_hello* str, rsa_util* rsa)
{
	//rsa encrypted data length
	short encrypted_length = (short)get_modulus_bytes(rsa->pub_key_rsa);
	unsigned char* encrypted_length_c = stoc(encrypted_length);
	//build version length
	unsigned char* temp_bvl = stoc(str->build_version_length);
	//game id
	unsigned char* temp_gid = ltoc(str->game_id);
	//encrypted guid length
	unsigned char* guid_length = stoc(encrypted_length);
	//encrypted guid
	unsigned char* encrypted_guid = pub_encrypt(str->guid, str->guid_length, rsa);
	//encrypted password
	unsigned char* encrypted_password = pub_encrypt(str->password, str->password_length, rsa);
	//encrypted secret length
	unsigned char* temp_sl = stoc(encrypted_length);
	//encrypted secret
	unsigned char* encrypted_secret = pub_encrypt(str->secret, str->secret_length, rsa);
	//key time length
	unsigned char* temp_kt = ltoc(str->key_time);
	//key length
	unsigned char* temp_kl = stoc(str->key_length);
	//key
	unsigned char* temp_rwl = stoc(str->__Rw_length);
	//_Rw
	unsigned char* temp_06ul = stoc(str->__06U_length);
	//_06U
	unsigned char* temp_lkl = stoc(str->__LK_length);
	//_LK
	unsigned char* temp_pfl = stoc(str->playplatform_length);
	//playplatform

	rotmg_packet* pkt = malloc(sizeof(rotmg_packet));

	long size = (4*2)+
				(2*9)+
				(sizeof(char)*str->build_version_length)+
				(sizeof(char)*encrypted_length*3)+
				(sizeof(char)*str->key_length)+
				(sizeof(char)*str->__Rw_length)+
				(sizeof(char)*str->__06U_length)+
				(sizeof(char)*str->__LK_length)+
				(sizeof(char)*str->playplatform_length);

	pkt->payload = malloc(size);
	pkt->type = HELLO_12351;
	pkt->length = size;

	int position = 0;

	//build_version_length
	memcpy(&(pkt->payload[position]), temp_bvl, 2);
	free(temp_bvl);
	position += 2;
	//build_version
	memcpy(&(pkt->payload[position]), str->build_version, str->build_version_length);
	position += str->build_version_length;
	//game_id
	memcpy(&(pkt->payload[position]), temp_gid, 4);
	free(temp_gid);
	position += 4;
	//guid_length
	memcpy(&(pkt->payload[position]), encrypted_length_c, 2);
	position += 2;
	//guid
	memcpy(&(pkt->payload[position]), encrypted_guid, encrypted_length);
	position += encrypted_length;
	//password_length
	memcpy(&(pkt->payload[position]), encrypted_length_c, 2);
	position += 2;
	//password
	memcpy(&(pkt->payload[position]), encrypted_password, encrypted_length);
	position += encrypted_length;
	//secret_length
	memcpy(&(pkt->payload[position]), encrypted_length_c, 2);
	position += 2;
	//secret
	memcpy(&(pkt->payload[position]), encrypted_secret, encrypted_length);
	position += encrypted_length;
	//key_time
	memcpy(&(pkt->payload[position]), temp_kt, 4);
	free(temp_kt);
	position += 4;
	//key_length
	memcpy(&(pkt->payload[position]), temp_kl, 2);
	free(temp_kl);
	position += 2;
	//key
	memcpy(&(pkt->payload[position]), str->key, str->key_length);
	position += str->key_length;
	//__Rw_length
	memcpy(&(pkt->payload[position]), temp_rwl, 2);
	free(temp_rwl);
	position += 2;
	//__Rw
	memcpy(&(pkt->payload[position]), str->__Rw, str->__Rw_length);
	position += str->__Rw_length;
	//__06U_length
	memcpy(&(pkt->payload[position]), temp_06ul, 2);
	free(temp_06ul);
	position += 2;
	//__06U
	memcpy(&(pkt->payload[position]), str->__06U, str->__06U_length);
	position += str->__06U_length;
	//__LK_length
	memcpy(&(pkt->payload[position]), temp_lkl, 2);
	free(temp_lkl);
	position += 2;
	//__LK
	memcpy(&(pkt->payload[position]), str->__LK, str->__LK_length);
	position += str->__LK_length;
	//playplatform_length
	memcpy(&(pkt->payload[position]), temp_pfl, 2);
	free(temp_pfl);
	position += 2;
	//playplatform
	memcpy(&(pkt->payload[position]), str->playplatform, str->playplatform_length);
	position += str->playplatform_length;

	//free encrypted length
	free(encrypted_length_c);

	return pkt;
}
