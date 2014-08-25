#ifndef rotmg_update_h

#define rotmg_update_h

#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../rotmg.h"
#include "../packet_ids.h"

typedef struct rotmg_packet_update {
	TileData[] Tiles;
	ObjectDef[] NewObjects;
	int RemovedObjectIds[];
} rotmg_packet_update;

rotmg_packet* rotmg_strtopkt_update (rotmg_packet_update* str);
rotmg_packet_update* rotmg_pkttostr_update (rotmg_packet* pkt);

#endif
