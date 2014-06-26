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
	unsigned char* temp_el = stoc(str->error_message_length);
	unsigned char* el = reverse_endian(2, temp_el);

	rotmg_packet* pkt = calloc(1, sizeof(rotmg_packet));

	long size = 2+
				(sizeof(char)*str->error_message_length);

	pkt->payload = calloc(1, size);
	pkt->type = FAILURE_2210;
	pkt->length = size;

	int position = 0;

	//error_message_length
	memcpy(&(pkt->payload[position]), el, 2);
	free(temp_el);
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
