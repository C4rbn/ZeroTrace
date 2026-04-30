#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct a_v4 { __u32 addr; };
struct a_v6 { struct in6_addr addr; };

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct a_v4);
    __type(value, __u64);
} m_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct a_v6);
    __type(value, __u64);
} m_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} m_state SEC(".maps");

#ifndef SEED
#define SEED 0x0
#endif

static __always_inline int handle_udp(void *data, void *data_end, void *ip_hdr, bool is_v6) {
    struct udphdr *udp;
    if (is_v6) {
        struct ipv6hdr *ip6 = ip_hdr;
        udp = (void *)ip6 + sizeof(*ip6);
    } else {
        struct iphdr *ip4 = ip_hdr;
        udp = (void *)ip4 + (ip4->ihl * 4);
    }

    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    if (udp->dest == bpf_htons(1337)) {
        __u64 ts = bpf_ktime_get_ns();
        if (is_v6) {
            struct ipv6hdr *ip6 = ip_hdr;
            bpf_map_update_elem(&m_v6, &ip6->saddr, &ts, BPF_ANY);
        } else {
            struct iphdr *ip4 = ip_hdr;
            struct a_v4 k = { .addr = ip4->saddr };
            bpf_map_update_elem(&m_v4, &k, &ts, BPF_ANY);
        }
        return XDP_DROP;
    }

    if (udp->dest == bpf_htons(65535)) {
        __u32 key = 0, val = 1;
        bpf_map_update_elem(&m_state, &key, &val, BPF_ANY);
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp")
int handle_ingress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 proto = eth->h_proto;
    void *cursor = eth + 1;

    if (proto == bpf_htons(ETH_P_8021Q)) {
        struct { __be16 tci; __be16 proto; } *vlan = cursor;
        if ((void *)(vlan + 1) > data_end) return XDP_PASS;
        proto = vlan->proto;
        cursor += 4;
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        if (ip->protocol == 47) {
            cursor += (ip->ihl * 4) + 4;
            ip = cursor;
            if ((void *)(ip + 1) > data_end) return XDP_PASS;
        }

        if (ip->protocol == IPPROTO_UDP) return handle_udp(data, data_end, ip, false);
    } 
    else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        if (ip6->nexthdr == IPPROTO_UDP) return handle_udp(data, data_end, ip6, true);
    }

    return XDP_PASS;
}

SEC("xdp")
int handle_egress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        struct a_v4 k = { .addr = ip->daddr };
        __u64 *ts = bpf_map_lookup_elem(&m_v4, &k);
        if (ts && (bpf_ktime_get_ns() - *ts < 3600000000000ULL)) return XDP_DROP;
    } 
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        __u64 *ts = bpf_map_lookup_elem(&m_v6, &ip6->daddr);
        if (ts && (bpf_ktime_get_ns() - *ts < 3600000000000ULL)) return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
