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
#include <bpf/bpf_endian.h>
#include <string.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct v4hdr{
    struct iphdr ip;
    struct udphdr udp;
};

#define L3_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define L3_TOT_OFF  (ETH_HLEN + offsetof(struct iphdr, tot_len))

#define L4_LEN_OFF  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, len))
#define L4_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
SEC("wg_egress")
int egress_wg(struct __sk_buff *skb){
    struct iphdr ip;
    struct udphdr udp;
    int udp_off;
    int payload_off;
    struct v4hdr v4 = {0};

    int i = 0;
    char buff[64] = {0};
    if(skb->protocol != __bpf_constant_htons(ETH_P_IP)){
        return TC_ACT_OK;
    }
    if(bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(struct iphdr)) < 0){
        return TC_ACT_OK;
    }
    udp_off = sizeof(struct iphdr);
    if(ip.ihl != 5 || ip.protocol != IPPROTO_UDP){
        return TC_ACT_OK;
    }
    if(bpf_skb_load_bytes(skb, ETH_HLEN + udp_off, &udp, sizeof(struct udphdr)) < 0){
        return TC_ACT_OK;
    }
    if(udp.dest != __bpf_constant_htons(9000)){
        return TC_ACT_OK;
    }
    v4.ip = ip;
    v4.udp = udp;
    char hello[6] = "World6";
    if(bpf_skb_change_tail(skb, skb->len + sizeof(hello), 0) < 0){
        return TC_ACT_OK;
    }

    payload_off = ETH_HLEN + ip.ihl * 4 + sizeof(struct udphdr) + bpf_ntohs(udp.len);
    bpf_printk("ip->tot_len[%d],udp->len[%d]", bpf_ntohs(ip.tot_len), bpf_ntohs(udp.len));


    //bpf_l4_csum_replace(skb, L4_CSUM_OFF, udp.len, new_udp_len, sizeof(__be16));
    //bpf_l3_csum_replace(skb, L3_CSUM_OFF, ip.tot_len, new_tot_len, sizeof(__be16));
/*
    if(bpf_skb_store_bytes(skb, L3_TOT_OFF, &new_tot_len, sizeof(__be16), 0) <0){
        return TC_ACT_SHOT;
    }
    if(bpf_skb_store_bytes(skb, L4_LEN_OFF, &new_udp_len, sizeof(__be16), 0) <0){
        return TC_ACT_SHOT;
    }

    if(bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(struct iphdr)) < 0){
        return TC_ACT_OK;
    }
    if(bpf_skb_load_bytes(skb, ETH_HLEN + udp_off, &udp, sizeof(struct udphdr)) < 0){
        return TC_ACT_OK;
    }
    */
    bpf_printk("ip->tot_len[%d],udp->len[%d]", bpf_ntohs(ip.tot_len), bpf_ntohs(udp.len));
    if(bpf_skb_store_bytes(skb, payload_off, &hello, sizeof(hello), 0) <0){
        return TC_ACT_SHOT;
    }
    //bpf_l4_csum_replace(skb, payload_off, 'H', hello, sizeof(char));
    return TC_ACT_OK;
}

