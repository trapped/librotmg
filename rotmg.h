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

typedef struct conn
{
	int client_socket;
	int remote_port;
	char* remote_address;

	long rc4_receive_length;
	char* rc4_receive;
	long rc4_send_length;
	char* rc4_send;
} conn;

typedef struct packet
{
	long length;
	unsigned char type;
	unsigned char* payload;
} packet;

conn*    rotmg_connect        (char* server, int port);
void     rotmg_disconnect     (conn* client);
packet* rotmg_receive_packet(conn* client);
void     rotmg_send_packet   (conn* client, packet* msg);

#endif