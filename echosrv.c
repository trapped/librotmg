#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define SERVERPORT 2050
#define SERVERADDRESS "127.0.0.1"

int main(int argc, char * argv[])
{
	int server_socket, connect_socket, retcode;
	socklen_t client_addr_len;
	struct sockaddr_in server_addr, client_addr;
	char buffer[1];
	char* client_address;
	
	if (((server_socket = socket(AF_INET,SOCK_STREAM,0))) == -1)
	{
		perror("Error in server socket()");
		exit(-1);
	}
		
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVERPORT);
	server_addr.sin_addr.s_addr = inet_addr(SERVERADDRESS);
	
	if ((retcode = bind (server_socket, (struct sockaddr*)  &server_addr, sizeof(server_addr))) == -1)
	{
		perror("Error in server socket bind()");
		exit(-1);
	}
	
	if ((retcode = listen(server_socket, 1)) == -1)
	{
		perror("Error in server socket listen()");
		exit(-1);
	}
	
	printf("Server ready (CTRL-C quits)\n");
	
	client_addr_len = sizeof(client_addr);
	
	while (1)
	{
		if ((connect_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) == -1)
		{
			perror("Error in accept()");
			close(server_socket);
			exit(-1);
		}
		
		client_address = inet_ntoa(client_addr.sin_addr);
		
		printf("\nClient @ %s connects on socket %d\n", client_address, connect_socket);
		
		while ((read(connect_socket, buffer, 1)) != -1)
		{
			printf("reading 1 byte\n");
			write(connect_socket, buffer, 1);
		}
		printf("exiting\n");

		//close(connect_socket);
	}
}