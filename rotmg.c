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

typedef struct message
{
	long length;
	char* payload;
} message;

//predeclare functions
//exported
conn*    rotmg_connect        (char* server, int port);
void     rotmg_disconnect     (conn* client);
message* rotmg_receive_message(conn* client);
void     rotmg_send_message   (conn* client, message* msg);
//unexported
char* reverse_endian(char* buffer);
char* ltoc(long num);

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

message* rotmg_receive_message(conn* client)
{
	//prepare message struct
	message* msg;

	//allocate buffer for server packet length (4 bytes)
	char* buffer_length = malloc(sizeof(char) * 4);
	//read 4 bytes into buffer_length
	int r = 0;
	errno = 0;
	while (r < 4 && errno == 0)
	{
		r += read(client->client_socket, buffer_length, 4 - r);
	}
	switch(errno)
	{
		case EBADF:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: invalid socket descriptor");
				return NULL;
			} break;		
		case ECONNRESET:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: connection reset");
				return NULL;
			} break;
		case ENOTCONN:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: socket not connected");
				return NULL;
			} break;
		case ETIMEDOUT:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: timed out");
				return NULL;
			} break;
	}
	//convert packet length from bytes to long
	//char* reversed_length = reverse_endian(buffer_length);
	long payload_length = (long)buffer_length;
	free(buffer_length);
	//free(reversed_length);
	msg->length = (payload_length);

	//allocate buffer for server packet payload
	char* buffer_payload = malloc(sizeof(char) * (payload_length));
	//read payload into buffer_payload
	r = 0;
	errno = 0;
	while(r < (payload_length) && errno == 0)
	{
		int h = read(client->client_socket, buffer_payload, (payload_length) - r);
		if (h == -1) { break; }
		r = r + h;
	}
	switch(errno)
	{
		case EBADF:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: invalid socket descriptor");
				return NULL;
			} break;		
		case ECONNRESET:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: connection reset");
				return NULL;
			} break;
		case ENOTCONN:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: socket not connected");
				return NULL;
			} break;
		case ETIMEDOUT:
			if (write(client->client_socket, buffer_length, 0) == -1)
			{
				perror("rotmg_receive: timed out");
				return NULL;
			} break;
	}
	//char* reversed_payload = reverse_endian(buffer_payload);
	msg->payload = malloc(sizeof(buffer_payload));
	strcpy(msg->payload, buffer_payload);
	free(buffer_payload);
	//msg->payload = reversed_payload;

	return msg;
}

void rotmg_send_message(conn* client, message* msg)
{
	errno = 0;
	//prepare buffer to send
	char* payload = malloc(sizeof(char) * msg->length + 4);
	//convert length to bytes
	long paylen = (long)sizeof(payload);
	char* payload_length = ltoc(paylen);
	memcpy(payload, payload_length, 4);
	//encrypt payload using rc4 key
	char* encrypted = rc4_crypt((long)msg->length, msg->payload, client->rc4_send_length, client->rc4_send);
	//copy payload
	memcpy(&payload[4], encrypted, msg->length);
	//write to socket
	write(client->client_socket, payload, msg->length + 4);
	//free memory
	free(payload);
	free(encrypted);
	switch(errno)
	{
		case EBADF:
			perror("rotmg_receive: invalid socket descriptor");
			return;
		case ECONNRESET:
			perror("rotmg_receive: connection reset");
			return;
		case ENOTCONN:
			perror("rotmg_receive: socket not connected");
			return;
		case ETIMEDOUT:
			perror("rotmg_receive: timed out");
			return;
	}
}

char* reverse_endian(char* buffer)
{
	char* temp = malloc(sizeof(buffer));
	int h = 0;
	for (int i = sizeof(buffer); i > 0; i--)
	{
		temp[h] = buffer[i];
		h++;
	}
	return temp;
}

char* ltoc(long num)
{
	char* temp = malloc(sizeof(char)*4);
	temp[3] = num;
	temp[2] = num >> 8;
	temp[1] = num >> 16;
	temp[0] = num >> 24;
	return temp;
}
