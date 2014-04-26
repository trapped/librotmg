#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "rc4.c"

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

//predeclare functions
//exported
conn*    rotmg_connect        (char* server, int port);
void     rotmg_disconnect     (conn* client);
packet*  rotmg_receive_packet (conn* client);
void     rotmg_send_packet    (conn* client, packet* pkt);
//unexported
char* reverse_endian(long length, char* buffer);
unsigned char* ltoc(long num);
long ctol(unsigned char* buffer);

conn* rotmg_connect(char* server, int port)
{
	conn* cli = malloc(sizeof(conn));
	char* srv = malloc(strlen(server)+1);
	strcpy(srv, server);
	cli->remote_address = srv;
	cli->remote_port = port;
	//open socket
	if ((cli->client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("rotmg_connect: socket error");
		exit(1);
	}
	//prepare socket
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(server);
	//connect socket
	if ((connect(cli->client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr))) == -1)
	{
		perror("rotmg_connect: connect error");
		exit(1);
	}
	//now connected
	printf("rotmg_connect: connected to %s\n", server);
	return cli;
}

void rotmg_disconnect(conn* client)
{
	//stop both receiving and transmitting
	errno = 0;
	shutdown(client->client_socket, 2);
	switch(errno)
	{
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
	switch(errno)
	{
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

packet* rotmg_receive_packet(conn* client)
{
	//prepare packet struct
	packet* pkt;

	//allocate buffer for server packet length (4 bytes)
	unsigned char* buffer_length = malloc(sizeof(char) * 4);
	//read 4 bytes into buffer_length
	int z = 0;
	int r = 0;
	errno = 0;
	while (r < 4 && (z = read(client->client_socket, buffer_length, 4 - r)) > 0)
	{
    	r += z;
	}
	if (z == -1)
	{
		switch(errno)
		{
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
	//char* reversed_length = reverse_endian(buffer_length);
	long payload_length = ctol(buffer_length);
	free(buffer_length);
	//free(reversed_length);
	//4 bytes of length and 1 of type
	pkt->length = payload_length - 5;
	//prepare packet type
	unsigned char* buffer_id = malloc(2);
	//read packet type
	r = 0;
	errno = 0;
	r = read(client->client_socket, buffer_id, 1);
	if (r == -1)
	{
		switch(errno)
		{
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
	//allocate buffer for server packet payload
	unsigned char* buffer_payload = malloc(sizeof(char) * (payload_length));
	//read payload into buffer_payload
	z = 0;
	errno = 0;
	r = 0;
	while (r < payload_length && (z = read(client->client_socket, buffer_payload, payload_length - r)) > 0)
	{
    	r += z;
	}
	if (z == -1)
	{
		switch(errno)
		{
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
	pkt->payload = malloc(sizeof(char)*payload_length);
	strcpy(pkt->payload, buffer_payload);
	free(buffer_payload);
	//pkt->payload = reversed_payload;

	return pkt;
}

void rotmg_send_packet(conn* client, packet* pkt)
{
	errno = 0;
	//prepare buffer to send
	unsigned char* payload = malloc(sizeof(char) * pkt->length + 5);
	//convert length to bytes
	long paylen = 5;
	paylen += pkt->length;
	unsigned char* payload_length = ltoc(paylen);
	memcpy(payload, payload_length, 4);
	//add packet type
	payload[4] = pkt->type;
	//encrypt payload using rc4 key
	unsigned char* encrypted = rc4_crypt((long)pkt->length, pkt->payload, client->rc4_send_length, client->rc4_send);
	//copy payload
	memcpy(&payload[5], encrypted, pkt->length);
	//write to socket
	int r = write(client->client_socket, payload, pkt->length + 5);
	if (r == -1)
	{
		switch(errno)
		{
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

char* reverse_endian(long length, char* buffer)
{
	char* temp = malloc(sizeof(char) * length);
	int h = 0;
	for (int i = length; i > 0; i--)
	{
		temp[h] = buffer[i];
		h++;
	}
	return temp;
}

unsigned char* ltoc(long num)
{
	unsigned char* temp = malloc(sizeof(char)*4);
	temp[0] = num;
	temp[1] = num >> 8;
	temp[2] = num >> 16;
	temp[3] = num >> 24;
	return temp;
}

long ctol(unsigned char* buffer)
{
	long temp = 0;
	temp += buffer[0];
	temp += buffer[1] << 8;
	temp += buffer[2] << 16;
	temp += buffer[3] << 24;
	return temp;
}
