/******************************************************************
    > File: common.h
    > Author: yuemingxing
    > Date: 23-4-12
******************************************************************/

#ifndef EBPF_TEST_COMMON_H
#define EBPF_TEST_COMMON_H

struct so_event{
    __be32 saddr;
    __be32 daddr;
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u32 ip_proto;
    __u32 pkt_type;
    __u32 ifindex;
};

#endif //EBPF_TEST_COMMON_H
