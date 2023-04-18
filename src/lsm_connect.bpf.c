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
//(*inet_conn_established)(struct sock *sk, struct sk_buff *skb)
SEC("lsm/inet_conn_established")
void BPF_PROG(lsm_inet_conn_established, struct sock *sk, struct sk_buff *skb){
    bpf_printk("hello\n");
    struct iphdr ip;

    bpf_core_read(&ip, sizeof(ip), skb->data + sizeof(struct ethhdr));
    bpf_printk("ip[%d]", ip.saddr);
}
#if 1
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket* sock, struct sockaddr *addr, int addrlen){
    struct connect_event *e = NULL;
    char comm[TASK_COMM_LEN] = {0};
    struct sockaddr_in temp;
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));
    __u16 dest = 0;
    __u32 daddr;
    e = bpf_ringbuf_reserve(&rb_lsm_connect, sizeof(*e), 0);
    if(!e){
        return 0;
    }
    e->caller_pid = caller_pid;
    memcpy(e->comm, comm, TASK_COMM_LEN);
    e->daddr = 0;
    e->port16[1] = 0;

    if(addr){
        bpf_core_read(&temp, sizeof(struct sockaddr_in), addr);
        e->daddr = temp.sin_addr.s_addr;
        e->port16[1] = temp.sin_port;
        daddr = temp.sin_addr.s_addr;
        dest = temp.sin_port;
        //bpf_printk("%s[%d] [%d:%d]", comm, caller_pid, e->daddr, e->port16[1]);
    }
    bpf_ringbuf_submit(e, 0);
    dest = __bpf_ntohs(dest);

    if(dest == 80){
        bpf_printk("%s[%d] [%d.%d.%d.%d:%d] rejected", comm, caller_pid,
               (daddr>>0)&0xff,(daddr>>8)&0xff,(daddr>>16)&0xff,(daddr>>24)&0xff,
               dest);
        return -EPERM;
    }
    return 0;
}
#endif