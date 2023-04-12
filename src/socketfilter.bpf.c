/******************************************************************
    > File: socketfilter.c
    > Author: yuemingxing
    > Date: 23-4-12
******************************************************************/
#include <linux/bpf.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#include "common.h"

#define IP_MF       0x2000
#define IP_OFFSET   0x1FFF



char LICENSE[] SEC("license") = "Dual BSD/GPL";
static char hello[] = "hello world";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff){
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int bpf_socket_handler(struct __sk_buff *skb){
    struct so_event *e;
    __u8 verlen;
    __u16 proto;
    __u32 nhoff = ETH_HLEN;

    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = __bpf_ntohs(proto);
    if (proto != ETH_P_IP)
        return 0;

    if (ip_is_fragment(skb, nhoff))
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

    if (e->ip_proto != IPPROTO_GRE) {
        bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->saddr), 4);
        bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->daddr), 4);
    }

    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
    bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->ports), 4);
    e->pkt_type = skb->pkt_type;
    e->ifindex = skb->ifindex;
    bpf_ringbuf_submit(e, 0);

    return skb->len;
}