#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../rotmg.h"
#include "../packet_ids.h"

typedef struct rotmg_packet_failure {
	short          error_message_length;
	unsigned char* error_message;
} rotmg_packet_failure;

rotmg_packet*
rotmg_strtopkt_failure (rotmg_packet_failure* str)
{
	rotmg_packet* pkt = malloc(sizeof(rotmg_packet));

	long size = (sizeof(char)*str->error_message_length)+
				2;

	pkt->payload = malloc(size);
	pkt->type = FAILURE_2210;
	pkt->length = size;

	int position = 0;

	//error_message_length
	unsigned char* temp_el = stoc(str->error_message_length);
	memcpy(
		&(pkt->payload[position]),
		temp_el,
		2);
	free(temp_el);
	position += 2;

	//error_message
	memcpy(
		&(pkt->payload[position]),
		str->error_message,
		str->error_message_length);
	position += str->error_message_length;

	return pkt;
}
