#ifndef rotmg_ping_h

#define rotmg_ping_h

#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../rotmg.h"
#include "../packet_ids.h"

typedef struct rotmg_packet_ping {
	int serial;
} rotmg_packet_ping;

rotmg_packet* rotmg_strtopkt_ping (rotmg_packet_ping* str);
rotmg_packet_ping* rotmg_pkttostr_ping (rotmg_packet* pkt);

#endif
