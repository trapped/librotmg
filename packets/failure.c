#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../rotmg.h"
#include "../packet_ids.h"

typedef struct rotmg_packet_failure {
	long		   error_id;
	short          error_message_length;
	unsigned char* error_message;
} rotmg_packet_failure;

rotmg_packet*
rotmg_strtopkt_failure (rotmg_packet_failure* str) {
	//error id
	unsigned char* temp_eid = ltoc(str->error_id);
	unsigned char* eid = reverse_endian(4, temp_eid);
	free(temp_eid);
	//error message length
	unsigned char* temp_el = stoc(str->error_message_length);
	unsigned char* el = reverse_endian(2, temp_el);
	free(temp_el);

	rotmg_packet* pkt = calloc(1, sizeof(rotmg_packet));

	long size = 2+
				(sizeof(char)*str->error_message_length);

	pkt->payload = calloc(1, size);
	pkt->type = FAILURE_2210;
	pkt->length = size;

	int position = 0;

	//error_id
	memcpy(&(pkt->payload[position]), eid, 4);
	free(eid);
	position += 4;

	//error_message_length
	memcpy(&(pkt->payload[position]), el, 2);
	free(el);
	position += 2;

	//error_message
	memcpy(
		&(pkt->payload[position]),
		str->error_message,
		str->error_message_length);
	position += str->error_message_length;

	return pkt;
}

rotmg_packet_failure*
rotmg_pkttostr_failure (rotmg_packet* pkt) {
	rotmg_packet_failure* str = calloc(1, sizeof(rotmg_packet_failure));
	//error id
	unsigned char* error_id = calloc(1, 4);
	memcpy(error_id, pkt->payload, 4);
	unsigned char* rev_error_id = reverse_endian(4, error_id);
	free(error_id);
	str->error_id = ctol(rev_error_id);
	free(rev_error_id);
	//error message length
	unsigned char* error_message_length = calloc(1, 2);
	memcpy(error_message_length, &(pkt->payload[4]), 2);
	unsigned char* rev_error_message_length = reverse_endian(2, error_message_length);
	free(error_message_length);
	str->error_message_length = ctol(rev_error_message_length);
	free(rev_error_message_length);
	//error message
	unsigned char* error_message = calloc(1, sizeof(char)*str->error_message_length);
	memcpy(error_message, &(pkt->payload[6]), str->error_message_length);
	str->error_message = error_message;
	return str;
}
