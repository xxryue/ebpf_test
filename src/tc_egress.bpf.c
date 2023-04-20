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
    struct iphdr ip;
    struct udphdr udp;
    int ip_offset, udp_offset;
    if(skb->protocol != __constant_htonl(ETH_P_IP)){
        return TC_ACT_OK;
    }
    ip_offset = ETH_HLEN;
    // read ip header
    if(bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        return TC_ACT_OK;
    }
    if(ip.protocol != IPPROTO_UDP){
        return TC_ACT_OK;
    }
    udp_offset = ip_offset + (ip.ihl << 2);
    // read udp header
    if(bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(struct udphdr)) < 0){
        return TC_ACT_OK;
    }

    bpf_skb_adjust_room(skb, 4*5, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET );


    return TC_ACT_OK;
}

