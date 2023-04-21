/******************************************************************
    > File: common.c
    > Author: yuemingxing
    > Date: 23-4-20
******************************************************************/

#include "common.h"
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
static int sock_init(void){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    return fd;
}

void server(uint16_t port){
    struct sockaddr_in addr = {0};
    int err;
    char buff[2048] = {0};
    int n;
    int fd = sock_init();
    if(fd == -1){
        printf("error: %s\n", strerror(errno));
        return;
    }
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    err = bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    if(err < 0){
        printf("error: %s\n", strerror(errno));
        close(fd);
        return;
    }

    while (1){
        n = recvfrom(fd, buff, sizeof(buff), 0, NULL, NULL);
        buff[n] = '\0';
        printf("recv:%s\n", buff);
        if(n == -1){
            printf("error: %s\n", strerror(errno));
            break;
        }
    }
    close(fd);
}
void client(const char *daddr, uint16_t dest){
    int fd;
    struct sockaddr_in server = {0};
    fd = sock_init();
    int n;
    char *msg = "Hello";
    if(fd == -1){
        printf("error: %s\n", strerror(errno));
        return;
    }
    server.sin_port = htons(dest);
    inet_pton(AF_INET, daddr, &server.sin_addr);
    server.sin_family = AF_INET;

    n = sendto(fd, msg, strlen(msg), 0, (struct sockaddr*)&server, sizeof(struct sockaddr_in));
    if(n == -1){
        printf("error[%s]\n", strerror(errno));
    }
    close(fd);
}