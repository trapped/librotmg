#include <stdio.h>
#include "rotmg.h"
#include "packets.h"
#include "rsa.h"
#include "packet_ids.h"

void test_send_norm(rotmg_conn* c);
void test_send_failure(rotmg_conn* c);
void test_send_hello(rotmg_conn* c);

int main(int argc, char const *argv[]) {
	//char* server = "76.100.53.170"; //case
	char* server = "69.140.1.203"; //case2
	//char* server = "127.0.0.1";
	//char* server = "91.53.233.49"; //fab
	//char* server = "213.66.248.78"; //don
	//char* server = "54.217.63.70"; //EUSouthWest
	int port = 2050;

	puts("connecting");
	rotmg_conn* connection = rotmg_connect(server, port);
	puts("connected");
	printf("socket id: %i\n", connection->client_socket);

	puts("setting up rc4");
	unsigned char rc4_sendk[] = {0x31, 0x1f, 0x80, 0x69, 0x14, 0x51, 0xc7, 0x1d, 0x09, 0xa1, 0x3a, 0x2a, 0x6e}; //0x1b for 123.5.1, 0x1d for 21.4.0
	unsigned char rc4_recvk[] = {0x72, 0xc5, 0x58, 0x3c, 0xaf, 0xb6, 0x81, 0x89, 0x95, 0xcd, 0xd7, 0x4b, 0x80};
	connection->rc4_send = rc4_sendk;
	connection->rc4_send_length = 13;
	connection->rc4_receive = rc4_recvk;
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

void test_send_norm(rotmg_conn* c) {
	puts("creating packet");
	rotmg_packet* msg = calloc(1, sizeof(rotmg_packet));
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

	if (recv == NULL) {
		puts("recv = NULL");
		exit(1);
	}

	printf("packet: length: %li id: %i data: %s\n", recv->length, recv->type, recv->payload);

	free(recv->payload);
	free(recv);
}

void test_send_failure(rotmg_conn* c) {
	puts("creating failure packet");

	rotmg_packet_failure* fail = calloc(1, sizeof(rotmg_packet_failure));
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

	if (recv == NULL) {
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

test_file_struct* get_pub_key() {
	FILE* pubfile = fopen("pubfsd", "rb");
	fseek(pubfile, 0, SEEK_END);
	long fsize = ftell(pubfile);
	rewind(pubfile);
	unsigned char* contents = calloc(1, fsize);
	fread(contents, fsize, 1, pubfile);
	fclose(pubfile);
	test_file_struct* res = calloc(1, sizeof(test_file_struct));
	res->data = contents;
	res->size = fsize;
	return res;
}

void test_send_hello(rotmg_conn* c) {
	test_file_struct* pubkey = get_pub_key();
	rsa_util* rsa = rsa_make(NULL, 0, pubkey->data, pubkey->size);

	puts("creating hello packet");

	rotmg_packet_hello* hello = calloc(1, sizeof(rotmg_packet_hello));

	hello->build_version = (unsigned char*)"21.4.0";
	hello->build_version_length = strlen((char*)hello->build_version);

	hello->game_id = -2;

	hello->guid = (unsigned char*)"trappedammy@pellero.it";
	hello->guid_length = strlen((char*)hello->guid);

	hello->password = (unsigned char*)"trapped";
	hello->password_length = strlen((char*)hello->password);

	hello->secret = (unsigned char*)"";
	hello->secret_length = strlen((char*)hello->secret);

	hello->key_time = -1;
	hello->key_length = 0;
	hello->key = (unsigned char*)"";

	rotmg_packet* msg = rotmg_strtopkt_hello(hello, rsa);
	if(msg == NULL) {
		puts("couldn't create packet");
		free(hello);
		return;
	} else {
		puts("created packet");
		free(hello);

		puts("sending data");
		rotmg_send_packet(c, msg);
		puts("sent data");

		free(msg->payload);
		free(msg);
	}
Receive:
	puts("receiving packet");
	rotmg_packet* recv = rotmg_receive_packet(c);
	puts("received packet");

	if (!recv) {
		puts("recv = NULL");
		exit(1);
	}

	printf("packet: length: %li id: %i\n", recv->length, recv->type);
	for(int i = 0; i < recv->length; i++) {
		printf("%02X ", recv->payload[i]);
	}
	printf("\n");
	if(recv->type == FAILURE_2210) {
		rotmg_packet_failure* failure = rotmg_pkttostr_failure(recv);
		printf("failure: %d %ld '%s'\n", failure->error_message_length, failure->error_id, failure->error_message);
		free(failure->error_message);
		free(failure);
		free(recv->payload);
		free(recv);
		goto Receive;
	}

	free(recv->payload);
	free(recv);
}
