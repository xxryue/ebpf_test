/******************************************************************
    > File: udp_server.c
    > Author: yuemingxing
    > Date: 23-4-20
******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include "common.h"


int main(int argc, char *argv[]){
    if(argc != 2){
        printf("Usage: %s 90\n", argv[0]);
        return 0;
    }
    server(atoi(argv[1]));
    return 0;
}