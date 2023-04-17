/******************************************************************
    > File: connect.bpf.c
    > Author: yuemingxing
    > Date: 23-4-13
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
}rb_connect SEC(".maps");
#if 0
SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx){
    __u32 caller_pid;
    struct connect_event *e = NULL;
    char comm[TASK_COMM_LEN];
    __u16 dest = ctx->user_port;
    __u32 daddr = ctx->user_ip4;
    caller_pid = bpf_get_current_pid_tgid() >>32;
    bpf_get_current_comm(&comm, sizeof(comm));
    e = bpf_ringbuf_reserve(&rb_connect, sizeof(*e), 0);
    if(!e){
        return 0;
    }
    e->caller_pid = caller_pid;
    memcpy(e->comm, comm, TASK_COMM_LEN);
    e->daddr = dest;
    e->port16[1] = dest;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif

SEC("ksyscall/connect")
int BPF_KPROBE_SYSCALL(connect_entry, int fd,  struct sockaddr *addr,int addrlen){
    struct connect_event *e = NULL;
    char comm[TASK_COMM_LEN] = {0};
    struct sockaddr_in *temp = (struct sockaddr_in*)addr;
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    e = bpf_ringbuf_reserve(&rb_connect, sizeof(*e), 0);
    if(!e){
        return 0;
    }
    e->caller_pid = caller_pid;
    memcpy(e->comm, comm, TASK_COMM_LEN);
    e->daddr = 0;
    e->port16[1] = 0;

    if(addr){
        BPF_CORE_READ_USER_INTO(&e->daddr, temp, sin_addr.s_addr);
        BPF_CORE_READ_USER_INTO(&e->port16[1], temp, sin_port);
        bpf_printk("%s[%d] [%d:%d]", comm, caller_pid, e->daddr, e->port16[1]);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

