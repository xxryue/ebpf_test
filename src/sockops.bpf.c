/******************************************************************
    > File: sk_msg.bpf.c
    > Author: yuemingxing
    > Date: 23-4-14
******************************************************************/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define FORCE_READ(x)   (*(volatile typeof(x)*)&x)

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

    key.saddr = __bpf_ntohl(ops->local_ip4);
    key.daddr = __bpf_ntohl(ops->remote_ip4);
    key.family = ops->family;
    key.source = ops->local_port;
    key.dest = __bpf_ntohs(FORCE_READ(ops->remote_port));

    ret = bpf_sock_hash_update(ops, &rb_sockops, &key, BPF_NOEXIST);
    if(ret != 0){
        bpf_printk("bpf_sock_hash_update failed[%d]\n", ret);
    }
    bpf_printk("op[%d], [%d.%d.%d.%d:%d->%d.%d.%d.%d:%d]\n",
               ops->op,
               (key.saddr>>24)&0xFF,(key.saddr>>16)&0xFF,
               (key.saddr>>8)&0xFF,(key.saddr>>0)&0xFF,key.source,
               (key.daddr>>24)&0xFF,(key.daddr>>16)&0xFF,
               (key.daddr>>8)&0xFF,(key.daddr>>0)&0xFF,key.dest);
}
#if 0
SEC("sockops")
int sockops_entry(struct bpf_sock_ops *sk_ops){
    //todo [tuple->connect]
    bpf_printk("hello\n");
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
#endif
SEC("sk_msg")
int sk_msg_entry(struct sk_msg_md *msg){
    // todo [pid->tuple]
    struct sock_key key = {0};
    //char comm[32] = {0};
    int caller_pid = bpf_get_current_pid_tgid() >> 32;
    key.saddr = __bpf_ntohl(msg->remote_ip4);
    key.daddr = __bpf_ntohl(msg->local_ip4);
    key.family = msg->family;
    key.source = msg->local_port;
    key.dest = __bpf_ntohs(FORCE_READ(msg->remote_port));
    //bpf_get_current_comm(comm, sizeof (comm));
    bpf_printk("pid[%d]", caller_pid);
#if 0
    bpf_printk("pid[%d],[%d.%d.%d.%d:%d->%d.%d.%d.%d:%d]\n",caller_pid,
               (key.saddr>>24)&0xFF,(key.saddr>>16)&0xFF,
               (key.saddr>>8)&0xFF,(key.saddr>>0)&0xFF,key.source,
               (key.daddr>>24)&0xFF,(key.daddr>>16)&0xFF,
               (key.daddr>>8)&0xFF,(key.daddr>>0)&0xFF,key.dest);
#endif
    return SK_PASS;
}




