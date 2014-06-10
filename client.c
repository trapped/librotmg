#include <stdio.h>
#include "rotmg.h"
#include "packets.h"
#include "rsa.h"

void test_send_norm(rotmg_conn* c);
void test_send_failure(rotmg_conn* c);
void test_send_hello(rotmg_conn* c);

int main(int argc, char const *argv[])
{
	//char* server = "76.100.53.170"; //case
	char* server = "127.0.0.1";
	//char* server = "84.144.254.164"; //fab
	//char* server = "213.66.248.78"; //don
	int port = 2050;

	puts("connecting");
	rotmg_conn* connection = rotmg_connect(server, port);
	puts("connected");
	printf("%i\n", connection->client_socket);

	puts("setting up rc4");
	char rc4[] = {0x31, 0x1f, 0x80, 0x69, 0x14, 0x51, 0xc7, 0x1b, 0x09, 0xa1, 0x3a, 0x2a, 0x6e};
	connection->rc4_send = rc4;
	connection->rc4_send_length = 13;
	connection->rc4_receive = rc4;
	connection->rc4_receive_length = 13;
	puts("set up rc4");

	//test_send_norm(connection);

	//test_send_failure(connection);

	test_send_hello(connection);

	puts("disconnecting");
	rotmg_disconnect(connection);
	puts("disconnected");

	return 0;
}

void test_send_norm(rotmg_conn* c)
{
	puts("creating packet");
	rotmg_packet* msg = malloc(sizeof(rotmg_packet));
	msg->length = (long)5;
	printf("%li\n", msg->length);
	msg->type = 0xff;
	msg->payload = (unsigned char*)"dada!";
	puts("created packet");

	puts("sending data");
	rotmg_send_packet(c, msg);
	puts("sent data");

	free(msg);
	puts("receiving packet");
	rotmg_packet* recv = rotmg_receive_packet(c);
	puts("received packet");

	if (recv == NULL)
	{
		puts("recv = NULL");
		exit(1);
	}

	printf("packet: length: %li id: %i data: %s\n", recv->length, recv->type, recv->payload);

	free(recv->payload);
	free(recv);
}

void test_send_failure(rotmg_conn* c)
{
	puts("creating failure packet");

	rotmg_packet_failure* fail = malloc(sizeof(rotmg_packet_failure));
	fail->error_message = (unsigned char*)"error message";
	fail->error_message_length = 13;

	rotmg_packet* msg = rotmg_strtopkt_failure(fail);
	puts("created packet");
	free(fail);

	puts("sending data");
	rotmg_send_packet(c, msg);
	puts("sent data");

	free(msg->payload);
	free(msg);
	puts("receiving packet");
	rotmg_packet* recv = rotmg_receive_packet(c);
	puts("received packet");

	if (recv == NULL)
	{
		puts("recv = NULL");
		exit(1);
	}

	printf("packet: length: %li id: %i data: %s\n", recv->length, recv->type, recv->payload);

	free(recv->payload);
	free(recv);
}

typedef struct test_file_struct {
	unsigned char* data;
	long size;
} test_file_struct;

test_file_struct* get_pub_key()
{
	FILE* pubfile = fopen("pub", "rb");
	fseek(pubfile, 0, SEEK_END);
	long fsize = ftell(pubfile);
	rewind(pubfile);
	unsigned char* contents = malloc(fsize);
	fread(contents, fsize, 1, pubfile);
	fclose(pubfile);
	test_file_struct* res = malloc(sizeof(test_file_struct));
	res->data = contents;
	res->size = fsize;
	return res;
}

void test_send_hello(rotmg_conn* c)
{
	test_file_struct* pubkey = get_pub_key();
	rsa_util* rsa = rsa_make(NULL, 0, pubkey->data, pubkey->size);

	puts("creating hello packet");

	rotmg_packet_hello* hello = malloc(sizeof(rotmg_packet_hello));

	hello->build_version = (unsigned char*)"123.5.1";
	hello->build_version_length = 7;

	hello->game_id = 12351;

	hello->guid = (unsigned char*)"xxx@gmail.com";
	hello->guid_length = 13;

	hello->password = (unsigned char*)"test";
	hello->password_length = 4;

	hello->secret = (unsigned char*)"secret";
	hello->secret_length = 6;

	hello->key_time = 13;
	hello->key_length = 7;
	hello->key = (unsigned char*)"key_length";

	hello->playplatform = (unsigned char*)"playplatform";
	hello->playplatform_length = 12;

	rotmg_packet* msg = rotmg_strtopkt_hello(hello, rsa);
	puts("created packet");
	free(hello);

	puts("sending data");
	rotmg_send_packet(c, msg);
	puts("sent data");

	free(msg->payload);
	free(msg);
	puts("receiving packet");
	rotmg_packet* recv = rotmg_receive_packet(c);
	puts("received packet");

	if (recv == NULL)
	{
		puts("recv = NULL");
		exit(1);
	}

	printf("packet: length: %li id: %i data: %s\n", recv->length, recv->type, recv->payload);

	free(recv->payload);
	free(recv);
}
