#ifndef rotmg_failure_h

#define rotmg_failure_h

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

rotmg_packet* rotmg_strtopkt_failure (rotmg_packet_failure* str);
rotmg_packet_failure* rotmg_pkttostr_failure (rotmg_packet* pkt);

#endif
