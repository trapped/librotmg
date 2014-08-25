#ifndef rotmg_mapInfo_h

#define rotmg_mapInfo_h

#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../rotmg.h"
#include "../packet_ids.h"

typedef struct rotmg_packet_mapInfo {
	int width;
	int height;
	unsigned char* name;
	unsigned char* clientWorldName;
	int difficulty;
	unsigned int fp;
	int background;
	bool showDisplays;
	unsigned char[] clientXML;
	unsigned char[] extraXML;
} rotmg_packet_mapInfo;

rotmg_packet* rotmg_strtopkt_mapInfo (rotmg_packet_mapInfo* str);
rotmg_packet_mapInfo* rotmg_pkttostr_mapInfo (rotmg_packet* pkt);

#endif
