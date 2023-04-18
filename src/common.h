/******************************************************************
    > File: common.h
    > Author: yuemingxing
    > Date: 23-4-12
******************************************************************/

#ifndef EBPF_TEST_COMMON_H
#define EBPF_TEST_COMMON_H
#define TASK_COMM_LEN   64



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

struct connect_event{
    __be32 saddr;
    __be32 daddr;
    union{
        __be32 ports;
        __be16 port16[2];
    };
    __u32 ip_proto;
    __u32 pkt_type;
    __u32 ifindex;
    __u32 caller_pid;
    __u8 rejected;
    char comm[TASK_COMM_LEN];
};

#endif //EBPF_TEST_COMMON_H
