#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int server_socket;

void handle_sigint(int sig_num)
{
	close(server_socket);
	
	exit(0);
}

int main(void)
{
	signal(SIGINT, handle_sigint);

	struct sockaddr_in server_address;
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(8080);
	bind(server_socket, (struct sockaddr *)&server_address,
		sizeof(server_address));
	listen(server_socket, 10);
	while (1)
	{
		int new_socket;
		struct sockaddr_in client_address;
		socklen_t client_address_len = sizeof(client_address);
		new_socket = accept(server_socket,
						(struct sockaddr *)&client_address, &client_address_len);
		char client_buffer[256];
		int len = recv(new_socket, client_buffer, 256, 0);
		client_buffer[len] = '\0';

		char server_buffer[30] = "This is a test msg for ftrace";

		send(new_socket, server_buffer, 29, 0);

		close(new_socket);
	}
	return 0;
}
