/******************************************************************
    > File: tc_egress.bpf.c
    > Author: yuemingxing
    > Date: 23-4-18
******************************************************************/

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("wg_egress")
int egress_wg(struct __sk_buff *skb){
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    int offset = sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct udphdr);
    struct bpf_sock_tuple tuple = {};
    struct bpf_sock *sk = NULL;
    struct ethhdr *eth = data;
    if(eth->h_proto != __constant_htons(ETH_P_IP)){
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if(ip->protocol != IPPROTO_UDP){
        return TC_ACT_OK;
    }
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    __be16 target_port = __constant_htons(9090);
    if(udp->dest != target_port){
        return TC_ACT_OK;
    }
    __be16 length = __constant_htons(1);
    if(udp->len < length){
        return TC_ACT_OK;
    }
    int left = (long)(data + offset) - (long)data_end;
    bpf_printk("left[%d]", left);
    if(left > 0){
        return TC_ACT_UNSPEC;
    }
    sk = bpf_sk_lookup_udp(skb, &tuple, sizeof(tuple.ipv4), 0, 0);
    char hello[24] = "Hello, World! Hello, TC!";
    offset += __be16_to_cpu(udp->len) + offset;
    bpf_skb_store_bytes(skb, offset, hello, sizeof(hello), BPF_F_RECOMPUTE_CSUM);
    return TC_ACT_OK;
}

