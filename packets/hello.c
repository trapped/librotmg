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
	//rsa encrypted data length (guid and password length)
	short encrypted_length = (short)get_modulus_bytes(rsa->pub_key_rsa);
	//build version length
	unsigned char* temp_bvl = stoc(str->build_version_length);
	unsigned char* bvl = reverse_endian(2, temp_bvl);
	free(temp_bvl);
	//game id
	unsigned char* temp_gid = ltoc(str->game_id);
	unsigned char* gid = reverse_endian(4, temp_gid);
	free(temp_gid);
	//encrypted guid to base64
	unsigned char* temp_encrypted_guid = (unsigned char*)pub_encrypt(str->guid, str->guid_length, rsa);
	unsigned char* encrypted_guid = (unsigned char*)b64_enc((int)encrypted_length, temp_encrypted_guid);
	free(temp_encrypted_guid);
	//encrypted guid length
	unsigned char* temp_encrypted_guid_length = stoc(strlen((char*)encrypted_guid));
	unsigned char* encrypted_guid_length = reverse_endian(2, temp_encrypted_guid_length);
	printf("gl:%02X %02X -> %d\n", encrypted_guid_length[0], encrypted_guid_length[1], (int)strlen((char*)encrypted_guid));
	free(temp_encrypted_guid_length);
	//encrypted password to base64
	unsigned char* temp_encrypted_password = (unsigned char*)pub_encrypt(str->password, str->password_length, rsa);
	unsigned char* encrypted_password = (unsigned char*)b64_enc((int)encrypted_length, temp_encrypted_password);
	free(temp_encrypted_password);
	puts((char*)encrypted_password);
	//encrypted password length
	unsigned char* temp_encrypted_password_length = stoc(strlen((char*)encrypted_password));
	unsigned char* encrypted_password_length = reverse_endian(2, temp_encrypted_password_length);
	free(temp_encrypted_password_length);
	//encrypted secret
	unsigned char* temp_encrypted_secret = (unsigned char*)pub_encrypt(str->secret, str->secret_length, rsa);
	unsigned char* encrypted_secret = (unsigned char*)b64_enc((int)encrypted_length, temp_encrypted_secret);
	free(temp_encrypted_secret);
	//encrypted secret length
	unsigned char* temp_encrypted_secret_length = stoc(strlen((char*)encrypted_secret));
	unsigned char* encrypted_secret_length = reverse_endian(2, temp_encrypted_secret_length);
	free(temp_encrypted_secret_length);
	//key time length
	unsigned char* temp_kt = ltoc(str->key_time);
	unsigned char* kt = reverse_endian(4, temp_kt);
	free(temp_kt);
	//key length
	unsigned char* temp_kl = stoc(str->key_length);
	unsigned char* kl = reverse_endian(2, temp_kl);
	free(temp_kl);
	//_Rw
	unsigned char* temp_rwl = stoc(str->__Rw_length);
	unsigned char* rwl = reverse_endian(2, temp_rwl);
	free(temp_rwl);
	//_06U
	unsigned char* temp_06ul = stoc(str->__06U_length);
	unsigned char* __06ul = reverse_endian(2, temp_06ul);
	free(temp_06ul);
	//_LK
	unsigned char* temp_lkl = stoc(str->__LK_length);
	unsigned char* lkl = reverse_endian(2, temp_lkl);
	free(temp_lkl);
	//playplatform
	unsigned char* temp_pfl = stoc(str->playplatform_length);
	unsigned char* pfl = reverse_endian(2, temp_pfl);
	free(temp_pfl);

	rotmg_packet* pkt = malloc(sizeof(rotmg_packet));

	long size = (6*2)+(2*9)+
				(sizeof(char)*str->build_version_length)+
				(sizeof(char)*strlen((char*)encrypted_guid))+
				(sizeof(char)*strlen((char*)encrypted_password))+
				(sizeof(char)*strlen((char*)encrypted_secret))+
				(sizeof(char)*str->key_length)+
				(sizeof(char)*str->__Rw_length)+
				(sizeof(char)*str->__06U_length)+
				(sizeof(char)*str->__LK_length)+
				(sizeof(char)*str->playplatform_length);

	pkt->payload = malloc(size);
	pkt->type = HELLO_2210;
	pkt->length = size;

	int position = 0;

	printf("g:%d p:%d s:%d\n", (int)strlen((char*)encrypted_guid), (int)strlen((char*)encrypted_password), (int)strlen((char*)encrypted_secret));

	//build_version_length
	memcpy(&(pkt->payload[position]), bvl, 2);
	free(bvl);
	position += 2;
	//build_version
	memcpy(&(pkt->payload[position]), str->build_version, str->build_version_length);
	position += str->build_version_length;
	//game_id
	memcpy(&(pkt->payload[position]), gid, 4);
	free(gid);
	position += 4;
	//guid_length
	memcpy(&(pkt->payload[position]), encrypted_guid_length, 2);
	free(encrypted_guid_length);
	position += 2;
	//guid
	memcpy(&(pkt->payload[position]), encrypted_guid, strlen((char*)encrypted_guid));
	position += strlen((char*)encrypted_guid);
	free(encrypted_guid);
	//password_length
	memcpy(&(pkt->payload[position]), encrypted_password_length, 2);
	free(encrypted_password_length);
	position += 2;
	//password
	memcpy(&(pkt->payload[position]), encrypted_password, strlen((char*)encrypted_password));
	position += strlen((char*)encrypted_password);
	free(encrypted_password);
	//secret_length
	memcpy(&(pkt->payload[position]), encrypted_secret_length, 2);
	free(encrypted_secret_length);
	position += 2;
	//secret
	memcpy(&(pkt->payload[position]), encrypted_secret, strlen((char*)encrypted_secret));
	position += strlen((char*)encrypted_secret);
	free(encrypted_secret);
	//key_time
	memcpy(&(pkt->payload[position]), kt, 4);
	free(kt);
	position += 4;
	//key_length
	memcpy(&(pkt->payload[position]), kl, 2);
	free(kl);
	position += 2;
	//key
	memcpy(&(pkt->payload[position]), str->key, str->key_length);
	position += str->key_length;
	//__Rw_length
	memcpy(&(pkt->payload[position]), rwl, 2);
	free(rwl);
	position += 2;
	//__Rw
	memcpy(&(pkt->payload[position]), str->__Rw, str->__Rw_length);
	position += str->__Rw_length;
	//__06U_length
	memcpy(&(pkt->payload[position]), __06ul, 2);
	free(__06ul);
	position += 2;
	//__06U
	memcpy(&(pkt->payload[position]), str->__06U, str->__06U_length);
	position += str->__06U_length;
	//__LK_length
	memcpy(&(pkt->payload[position]), lkl, 2);
	free(lkl);
	position += 2;
	//__LK
	memcpy(&(pkt->payload[position]), str->__LK, str->__LK_length);
	position += str->__LK_length;
	//playplatform_length
	memcpy(&(pkt->payload[position]), pfl, 2);
	free(pfl);
	position += 2;
	//playplatform
	memcpy(&(pkt->payload[position]), str->playplatform, str->playplatform_length);
	position += str->playplatform_length;

	return pkt;
}
