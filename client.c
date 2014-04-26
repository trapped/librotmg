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

	puts("creating packet");
	packet* msg = malloc(sizeof(packet));
	msg->length = (long)5;
	printf("%li\n", msg->length);
	msg->type = 0xff;
	msg->payload = (unsigned char*)"dada!";
	puts("created packet");

	puts("sending data");
	rotmg_send_packet(connection, msg);
	puts("sent data");

	free(msg);
	sleep(5);
	puts("receiving packet");
	packet* recv = rotmg_receive_packet(connection);
	puts("received packet");

	if (recv == NULL)
	{
		puts("recv = NULL");
		return 1;
	}

	printf("packet: length: %li id: %i data: %s\n", recv->length, recv->type, recv->payload);

	free(recv);

	puts("disconnecting");
	rotmg_disconnect(connection);
	puts("disconnected");

	return 0;
}