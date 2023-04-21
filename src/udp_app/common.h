/******************************************************************
    > File: common.h
    > Author: yuemingxing
    > Date: 23-4-20
******************************************************************/

#ifndef EBPF_TEST_COMMON_H
#define EBPF_TEST_COMMON_H

#include <stdint.h>

void server(uint16_t port);
void client(const char *daddr, uint16_t dest);

#endif //EBPF_TEST_COMMON_H
