/******************************************************************
    > File: sk_msg.bpf.c
    > Author: yuemingxing
    > Date: 23-4-14
******************************************************************/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct sock_key{
    __u32 saddr;
    __u32 daddr;
    __u16 source, dest;
    __u32 family;
    __u32 pid;
    __u32 protocol;
}__attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 65536);
    __uint(map_flags, 0);
}rb_sockops SEC(".maps");

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *ops){
    struct sock_key key = {0};
    int ret;

    key.saddr = ops->local_ip4;
    key.daddr = ops->remote_ip4;
    key.family = 2;
    key.source = ops->local_port;
    key.dest = ops->remote_port;

    ret = bpf_sock_hash_update(ops, &rb_sockops, &key, BPF_NOEXIST);
    if(ret != 0){
        bpf_printk("bpf_sock_hash_update failed[%d]\n", ret);
    }

}

SEC("sockops")
int sockops_entry(struct bpf_sock_ops *sk_ops){
    switch (sk_ops->op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            if(sk_ops->family == 2){
                bpf_sock_ops_ipv4(sk_ops);
            }
            break;
        default:
            break;
    }
    return 0;
}

SEC("sk_msg")
int sk_msg_entry(struct sk_msg_md *msg){
    struct sock_key key = {0};
    
    return SK_PASS;
}




