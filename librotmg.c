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
} conn;

typedef struct message
{
	long length;
	char* payload;
} message;

//predeclare functions
//exported
conn* rotmg_connect(char* server, int port);
void rotmg_disconnect(conn* client);
message* rotmg_receive_message(conn* client);
void rotmg_send_message(conn* client, message* msg);
//unexported
char* reverse_endian(char* buffer);
unsigned long ctoul(char* buffer);

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

	errno = 0;
	//allocate buffer for server packet length (4 bytes)
	char* buffer_length = malloc(sizeof(char) * 4);
	//read 4 bytes into buffer_length
	int r = 0;
	while (r < 4 && errno == 0)
	{
		r = r + read(client->client_socket, buffer_length, 4 - r);
	}
	switch(errno)
	{
		case EBADF:
			perror("rotmg_receive: invalid socket descriptor");
			return NULL;
		case ECONNRESET:
			perror("rotmg_receive: connection reset");
			return NULL;
		case ENOTCONN:
			perror("rotmg_receive: socket not connected");
			return NULL;
		case ETIMEDOUT:
			perror("rotmg_receive: timed out");
			return NULL;
	}
	//convert packet length from bytes to long
	char* reversed_length = reverse_endian(buffer_length);
	unsigned long payload_length = ctoul(reversed_length);
	free(buffer_length);
	free(reversed_length);
	msg->length = payload_length;

	errno = 0;
	//allocate buffer for server packet payload
	char* buffer_payload = malloc(sizeof(char) * payload_length);
	//read payload into buffer_payload
	r = 0;
	while(r < payload_length && errno == 0)
	{
		r = r + read(client->client_socket, buffer_payload, payload_length - r);
	}
	switch(errno)
	{
		case EBADF:
			perror("rotmg_receive: invalid socket descriptor");
			return NULL;
		case ECONNRESET:
			perror("rotmg_receive: connection reset");
			return NULL;
		case ENOTCONN:
			perror("rotmg_receive: socket not connected");
			return NULL;
		case ETIMEDOUT:
			perror("rotmg_receive: timed out");
			return NULL;
	}
	char* reversed_payload = reverse_endian(buffer_payload);
	free(buffer_payload);
	msg->payload = reversed_payload;

	return msg;
}

void rotmg_send_message(conn* client, message* msg)
{
	errno = 0;
	
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

unsigned long ctoul(char* buffer)
{
	unsigned long temp;
	temp = (unsigned long) buffer[3];
	temp |= ((unsigned long) buffer[2]) << 8;
	temp |= ((unsigned long) buffer[1]) << 16;
	temp |= ((unsigned long) buffer[0]) << 24;
	return temp;
}
