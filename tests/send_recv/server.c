#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/signal.h>

int listenfd;
int is_running = 1;

void handle_sigint(int sig_num)
{
    is_running = 0;
    close(listenfd);
} 

int main(void)
{
    signal(SIGINT, handle_sigint);
    int connfd;
    struct sockaddr_in serv_addr; 
    char client_msg[1025];
    char server_msg[1025];
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        return 1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(5432);
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        return 2;
    }
    if (listen(listenfd, 10) == -1)
    {
        return 3;
    }
    while (is_running)
    {
        connfd = accept(listenfd, NULL, NULL);
        int len = recv(connfd, client_msg, 1024, 0);
        client_msg[len] = '\0';
        if (len > 0)
        {
            printf("Server received: %s.\n", client_msg);
            printf("Client message length: %ld.\n", strlen(client_msg));
            snprintf(server_msg, 1024, "message from server with PID = %d", getpid());
            send(connfd, server_msg, strlen(server_msg), 0);
        }
        close(connfd);
    }
    printf("Server exited.\n");
    return 0;
}
