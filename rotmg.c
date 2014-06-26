#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "utils.h"
#include "rc4.h"

//structs

typedef struct rotmg_conn {
	int   client_socket;
	int   remote_port;
	char* remote_address;

	long  rc4_receive_length;
	unsigned char* rc4_receive;
	long  rc4_send_length;
	unsigned char* rc4_send;
} rotmg_conn;

typedef struct rotmg_packet {
	long           length;
	unsigned char  type;
	unsigned char* payload;
} rotmg_packet;

//prototypes

rotmg_conn*   rotmg_connect        (char* server, int port);
void          rotmg_disconnect     (rotmg_conn* client);
rotmg_packet* rotmg_receive_packet (rotmg_conn* client);
void          rotmg_send_packet    (rotmg_conn* client, rotmg_packet* pkt);

//functions

rotmg_conn*
rotmg_connect (char* server, int port) {
	rotmg_conn* cli = calloc(1, sizeof(rotmg_conn));
	char* srv = calloc(1, strlen(server)+1);
	strcpy(srv, server);
	cli->remote_address = srv;
	cli->remote_port = port;
	//open socket
	int flag = 1;
	if ((cli->client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1 || (setsockopt(cli->client_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int))) == -1) {
		perror("rotmg_connect: socket error");
		exit(1);
	}
	//prepare socket
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(server);
	//connect socket
	if ((connect(cli->client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr))) == -1) {
		perror("rotmg_connect: connect error");
		exit(1);
	}
	//now connected
	printf("rotmg_connect: connected to %s\n", server);
	return cli;
}

void
rotmg_disconnect (rotmg_conn* client) {
	//stop both receiving and transmitting
	errno = 0;
	shutdown(client->client_socket, 2);
	switch(errno) {
		case EBADF:
			perror("rotmg_disconnect: invalid socket descriptor");
			return;
		case ENOTSOCK:
			perror("rotmg_disconnect: invalid socket");
			return;
		case ENOTCONN:
			perror("rotmg_disconnect: socket not connected");
			return;
	}
	//close the socket
	errno = 0;
	close(client->client_socket);
	switch(errno) {
		case EBADF:
			perror("rotmg_disconnect: invalid socket descriptor");
			return;
		case EINTR:
			perror("rotmg_disconnect: interrupted by signal");
			return;
		case EIO:
			perror("rotmg_disconnect: i/o error");
			return;
	}
	//free connection memory
	free(client->remote_address);
	free(client);
}

rotmg_packet*
rotmg_receive_packet (rotmg_conn* client) {
	//prepare packet struct
	rotmg_packet* pkt = calloc(1, sizeof(rotmg_packet));

	//allocate buffer for server packet length (4 bytes)
	unsigned char* buffer_length = calloc(1, sizeof(char) * 4);
	//read 4 bytes into buffer_length
	int z = 0;
	int r = 0;
	errno = 0;
	while (r < 4 && (z = recv(client->client_socket, buffer_length, 4 - r, MSG_WAITALL)) > 0) {
    	r += z;
	}
	if (z == -1) {
		switch(errno) {
			case EBADF:
				perror("rotmg_receive_packet: invalid socket descriptor");
				return NULL;
			case ECONNRESET:
				perror("rotmg_receive_packet: connection reset");
				return NULL;
			case ENOTCONN:
				perror("rotmg_receive_packet: socket not connected");
				return NULL;
			case ETIMEDOUT:
				perror("rotmg_receive_packet: timed out");
				return NULL;
		}
	}
	//convert packet length from bytes to long
	unsigned char* buffer_lengthl = reverse_endian(4, buffer_length);
	long payload_length = ctol(buffer_lengthl);
	//free(buffer_lengthl);
	printf("recv-len: %ld\n", payload_length);
	free(buffer_length);
	free(buffer_lengthl);
	//4 bytes of length and 1 of type
	pkt->length = payload_length - 5;
	//prepare packet type
	unsigned char* buffer_id = calloc(1, 1);
	//read packet type
	r = 0;
	errno = 0;
	r = recv(client->client_socket, buffer_id, 1, MSG_WAITALL);
	if (r == -1) {
		switch(errno) {
			case EBADF:
				perror("rotmg_receive_packet: invalid socket descriptor");
				return NULL;
			case ECONNRESET:
				perror("rotmg_receive_packet: connection reset");
				return NULL;
			case ENOTCONN:
				perror("rotmg_receive_packet: socket not connected");
				return NULL;
			case ETIMEDOUT:
				perror("rotmg_receive_packet: timed out");
				return NULL;
		}
	}
	pkt->type = buffer_id[0];
	free(buffer_id);
	//allocate buffer for server packet payload
	unsigned char* buffer_payload = calloc(1, sizeof(char) * (payload_length));
	//read payload into buffer_payload
	z = 0;
	errno = 0;
	r = 0;
	while (r < payload_length - 5 && (z = recv(client->client_socket, buffer_payload, (payload_length - 5) - r, MSG_WAITALL)) > 0) {
		r += z;
	}
	if (z == -1) {
		switch(errno) {
			case EBADF:
				perror("rotmg_receive_packet: invalid socket descriptor");
				return NULL;
			case ECONNRESET:
				perror("rotmg_receive_packet: connection reset");
				return NULL;
			case ENOTCONN:
				perror("rotmg_receive_packet: socket not connected");
				return NULL;
			case ETIMEDOUT:
				perror("rotmg_receive_packet: timed out");
				return NULL;
		}
	}
	//char* reversed_payload = reverse_endian(buffer_payload);
	//decrypt packet
	unsigned char* encrypted = rc4_crypt((long)payload_length - 5, buffer_payload, client->rc4_receive_length, client->rc4_receive);
	//copy payload
	pkt->payload = calloc(1, sizeof(char)*payload_length-5);
	memcpy(pkt->payload, encrypted, payload_length-5);
	free(buffer_payload);
	free(encrypted);
	//pkt->payload = reversed_payload;

	return pkt;
}

void
rotmg_send_packet (rotmg_conn* client, rotmg_packet* pkt) {
	errno = 0;
	//prepare buffer to send
	unsigned char* payload = calloc(1, sizeof(char) * pkt->length + 5);
	//convert length to bytes
	long paylen = 5;
	paylen += pkt->length;
	printf("paylen: %d = 5 + %d\n", (int)paylen, (int)pkt->length);
	unsigned char* payload_length = ltoc(paylen);
	unsigned char* payload_lengthl = reverse_endian(4, payload_length);
	memcpy(payload, payload_lengthl, 4);
	free(payload_lengthl);
	//add packet type
	payload[4] = pkt->type;
	//encrypt payload using rc4 key
	unsigned char* encrypted = rc4_crypt((long)pkt->length, pkt->payload, client->rc4_send_length, client->rc4_send);
	//copy payload
	memcpy(&payload[5], encrypted, pkt->length);
	//write to socket
	int r = write(client->client_socket, payload, pkt->length + 5);
	if (r == -1) {
		switch(errno) {
			case EBADF:
				perror("rotmg_receive_packet: invalid socket descriptor");
				return;
			case ECONNRESET:
				perror("rotmg_receive_packet: connection reset");
				return;
			case ENOTCONN:
				perror("rotmg_receive_packet: socket not connected");
				return;
			case ETIMEDOUT:
				perror("rotmg_receive_packet: timed out");
				return;
		}
	}
	//free memory
	free(payload);
	free(payload_length);
	free(encrypted);
}
