#ifndef rotmg_h

#define rotmg_h

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

//structs

typedef struct rotmg_conn
{
	int   client_socket;
	int   remote_port;
	char* remote_address;

	long  rc4_receive_length;
	char* rc4_receive;
	long  rc4_send_length;
	char* rc4_send;
} rotmg_conn;

typedef struct rotmg_packet
{
	long           length;
	unsigned char  type;
	unsigned char* payload;
} rotmg_packet;

//functions

rotmg_conn*    rotmg_connect        (char* server, int port);
void           rotmg_disconnect     (rotmg_conn* client);
rotmg_packet*  rotmg_receive_packet (rotmg_conn* client);
void           rotmg_send_packet    (rotmg_conn* client, rotmg_packet* msg);

#endif