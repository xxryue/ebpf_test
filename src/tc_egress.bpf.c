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

#define EXPAND_LENGTH       20

#define L3_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define L3_TOT_OFF  (ETH_HLEN + offsetof(struct iphdr, tot_len))

#define L4_LEN_OFF  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, len))
#define L4_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
SEC("wg_egress")
int egress_wg(struct __sk_buff *skb){
    struct iphdr ip;
    struct udphdr udp;
    int ip_offset, udp_offset;
    long err;
    if(skb->protocol != __bpf_constant_htons(ETH_P_IP)){
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
    if(udp.dest != __bpf_constant_ntohs(9000)){
        return TC_ACT_OK;
    }
    bpf_printk("ip.tot_len[%d], udp.len[%d]", bpf_ntohs(ip.tot_len), bpf_ntohs(udp.len));
#if 0
    // cannot expand data to payload
    // expand tail
    __u16 payload_offset = udp_offset + bpf_ntohs(udp.len);
    bpf_printk("payload_offset[%d]", payload_offset);
    char tail[10] = {'0','1','2','3','4',
                     '5','6','7','8','9'};
    bpf_skb_change_tail(skb, EXPAND_LENGTH, 0);
    __be16 old_len = bpf_ntohs(ip.tot_len);
    __be16 new_len = bpf_htons(old_len + sizeof(tail));
    bpf_l3_csum_replace(skb, L3_CSUM_OFF, old_len, new_len, sizeof(__be16));
    bpf_skb_store_bytes(skb, L3_TOT_OFF, &new_len, sizeof(__be16), 0);
    old_len = bpf_ntohs(udp.len);
    new_len = bpf_htons(old_len + sizeof(tail));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, old_len, new_len, sizeof(__be16));
    bpf_skb_store_bytes(skb, L4_LEN_OFF, &new_len, sizeof(__be16), 0);
    if((err = bpf_skb_store_bytes(skb, payload_offset - 5, tail, sizeof(tail), BPF_F_RECOMPUTE_CSUM)) < 0){
        // this routine always failed
        bpf_printk("bpf_skb_store_bytes failed, err[%ld]", err);
    }

    if(bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        return TC_ACT_OK;
    }if(bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(struct udphdr)) < 0){
        return TC_ACT_OK;
    }
    bpf_printk("ip.tot_len[%d], udp.len[%d]", bpf_ntohs(ip.tot_len), bpf_ntohs(udp.len));
#endif

#if 0
    
#endif
    return TC_ACT_OK;
}

