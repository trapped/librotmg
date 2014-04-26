#include <stdio.h>
#include "rotmg.h"

int main(int argc, char const *argv[])
{
	//char* server = "76.100.53.170";
	char* server = "127.0.0.1";
	int port = 2050;

	puts("connecting");
	conn* connection = rotmg_connect(server, port);
	puts("connected");
	printf("%i\n", connection->client_socket);

	puts("setting up rc4");
	char rc4[] = {0x31, 0x1f, 0x80, 0x69, 0x14, 0x51, 0xc7, 0x1b, 0x09, 0xa1, 0x3a, 0x2a, 0x6e};
	connection->rc4_send = rc4;
	connection->rc4_send_length = 13;
	puts("set up rc4");

	puts("creating message");
	message* msg = malloc(sizeof(message));
	msg->length = (long)5;
	printf("%li\n", msg->length);
	msg->payload = (char*)"dada!";
	puts("created message");

	puts("sending data");
	rotmg_send_message(connection, msg);
	puts("sent data");

	free(msg);
	sleep(5);
	puts("receiving message");
	message* recv = rotmg_receive_message(connection);
	puts("received message");

	printf("message length: %li; message data: %s\n", recv->length, recv->payload);

	free(recv);

	puts("disconnecting");
	rotmg_disconnect(connection);
	puts("disconnected");

	return 0;
}