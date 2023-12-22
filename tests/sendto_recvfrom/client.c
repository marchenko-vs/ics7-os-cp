#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    int sockfd;
    char client_msg[1025], server_msg[1025];
    struct sockaddr_in serv_addr; 
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Can't socket.\n");
        return 1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5432);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        perror("Can't inet_pton.\n");
        return 2;
    } 
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        perror("Can't connect.\n");
        return 3;
    }
    snprintf(client_msg, 1024, "message from client with PID = %d", getpid());
    sendto(sockfd, client_msg, strlen(client_msg), 0, NULL, 0);
    int len = recvfrom(sockfd, server_msg, 1024, 0, NULL, 0);
    server_msg[len] = '\0';
    if (len > 0)
    {
        printf("Client received: %s.\n", server_msg);
        printf("Server message length: %ld.\n", strlen(server_msg));
    }
    printf("Client exited.\n");
    return 0;
}
