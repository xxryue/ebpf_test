/******************************************************************
    > File: lsm_connect.bpf.c
    > Author: yuemingxing
    > Date: 23-4-17
******************************************************************/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <string.h>
#include <errno.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
}rb_lsm_connect SEC(".maps");
#if 0
//(*inet_conn_established)(struct sock *sk, struct sk_buff *skb)
SEC("lsm/inet_conn_established")
void BPF_PROG(lsm_inet_conn_established, struct sock *sk, struct sk_buff *skb){
    bpf_printk("hello\n");
    __u16 dest = 0;
    __u16 source = 0;
    __u32 daddr;
    __u32 saddr = 0;
    struct sock_common skc = {0};
    char comm[TASK_COMM_LEN] = {0};
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_core_read(&skc, sizeof(struct sock_common), sk);
    struct connect_event *e = NULL;
    e = bpf_ringbuf_reserve(&rb_lsm_connect, sizeof(*e), 0);
    if(!e){
        return;
    }

    e->caller_pid = caller_pid;
    memcpy(e->comm, comm, TASK_COMM_LEN);
    e->daddr = skc.skc_daddr;
    e->port16[1] = skc.skc_dport;
    e->saddr = skc.skc_rcv_saddr;
    e->port16[0] = skc.skc_num;
    bpf_ringbuf_submit(e, 0);

#if 0
    bpf_core_read(&saddr, sizeof(__u32), ((__u8*)sk) + sizeof(struct sock) + sizeof(struct ipv6_pinfo*));
    bpf_core_read(&source, sizeof(__u16), ((__u8*)sk) + sizeof(struct sock) +  + sizeof(struct ipv6_pinfo*) +
            sizeof(__be32) + sizeof(__s16) + sizeof(__u16) + sizeof(struct ip_options_rcu*));
    saddr = __bpf_ntohl(saddr);
    source = __bpf_ntohs(source);
#endif

    saddr = __bpf_ntohl(skc.skc_rcv_saddr);
    source = __bpf_ntohs(skc.skc_num);
    bpf_printk("ip[%d.%d.%d.%d:%d]", (saddr >> 24)&0xFF,(saddr >> 16)&0xFF,
               (saddr >> 8)&0xFF,(saddr >> 0)&0xFF,source);

}
#endif
#if 0
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket* sock, struct sockaddr *addr, int addrlen){
    struct connect_event *e = NULL;
    char comm[TASK_COMM_LEN] = {0};
    struct sockaddr_in temp = {0};
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));
    e = bpf_ringbuf_reserve(&rb_lsm_connect, sizeof(*e), 0);
    if(!e){
        return 0;
    }

    e->caller_pid = caller_pid;
    memcpy(e->comm, comm, TASK_COMM_LEN);
    bpf_core_read(&temp, sizeof(struct sockaddr_in), addr);
    e->daddr = temp.sin_addr.s_addr;
    e->port16[1] = temp.sin_port;
    bpf_printk("%s[%d] [%d:%d]", comm, caller_pid, e->daddr, e->port16[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif

#if 1
//int (*socket_sendmsg)(struct socket *sock, struct msghdr *msg,int size);
SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size){
    struct sock_common skc = {0};
    bpf_core_read(&skc, sizeof(struct sock_common), sock->sk);
    char comm[TASK_COMM_LEN] = {0};
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));
    __u16 dport = __bpf_ntohs(skc.skc_dport);
    if(skc.skc_family == 2){
        if((sock->type&SOCK_STREAM) == SOCK_STREAM){
            bpf_printk("is SOCK_STREAM");
        }
        if((sock->type&SOCK_DGRAM) == SOCK_DGRAM){
            bpf_printk("is SOCK_DGRAM");
        }
        struct connect_event *e = NULL;
        e = bpf_ringbuf_reserve(&rb_lsm_connect, sizeof(*e), 0);
        if(!e){
            return 0;
        }
        e->caller_pid = caller_pid;
        memcpy(e->comm, comm, TASK_COMM_LEN);
        e->daddr = skc.skc_daddr;
        e->port16[1] = skc.skc_dport;
        e->saddr = skc.skc_rcv_saddr;
        e->port16[0] = skc.skc_num;

        bpf_printk("saddr[%u],source[%d],daddr[%u],dest[%d]",e->saddr,
                   e->port16[0], e->daddr, e->port16[1]);

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

#endif