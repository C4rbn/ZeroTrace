#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct packet_info {
    __u32 src_addr[4];
    __u32 dst_addr[4];
    __u32 protocol;
    __u32 version; 
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} PACKET_EVENTS SEC(".maps");

SEC("xdp")
int xdp_mutate(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct packet_info info = {0};
    __u16 h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        ip->ttl = 64;
        tcp->window = bpf_htons(0xFAF0); 
        info.version = 4;
        info.src_addr[0] = ip->saddr;
        info.dst_addr[0] = ip->daddr;
        info.protocol = IPPROTO_TCP;
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        if (ip6->nexthdr != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        ip6->hop_limit = 64;
        tcp->window = bpf_htons(0xFAF0);
        info.version = 6;
        __builtin_memcpy(info.src_addr, &ip6->saddr, 16);
        __builtin_memcpy(info.dst_addr, &ip6->daddr, 16);
        info.protocol = IPPROTO_TCP;
    } else {
        return XDP_PASS;
    }
    bpf_perf_event_output(ctx, &PACKET_EVENTS, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
