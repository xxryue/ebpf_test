/******************************************************************
    > File: udp_client.c
    > Author: yuemingxing
    > Date: 23-4-20
******************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "common.h"
int main(int argc, char *argv[]){
    if(argc != 3){
        printf("Usage: %s 192.168.1.100 90\n", argv[0]);
        return 0;
    }
    client(argv[1], atoi(argv[2]));
    return 0;
}
