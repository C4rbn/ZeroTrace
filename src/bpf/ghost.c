#include <stdbool.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct a_v4 { __u32 a; };
struct a_v6 { struct in6_addr a; };

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
} m_kill SEC(".maps");

static __always_inline int process_udp(void *data_end, void *ih, bool is_v6) {
    struct udphdr *u;
    if (is_v6) {
        struct ipv6hdr *ip6 = ih;
        u = (void *)ip6 + sizeof(*ip6);
    } else {
        struct iphdr *ip4 = ih;
        u = (void *)ip4 + (ip4->ihl * 4);
    }

    if ((void *)(u + 1) > data_end) return XDP_PASS;

    if (u->dest == bpf_htons(1337)) {
        __u64 ts = bpf_ktime_get_ns();
        if (is_v6) {
            struct ipv6hdr *ip6 = ih;
            bpf_map_update_elem(&m_v6, &ip6->saddr, &ts, BPF_ANY);
        } else {
            struct iphdr *ip4 = ih;
            bpf_map_update_elem(&m_v4, &ip4->saddr, &ts, BPF_ANY);
        }
        return XDP_DROP;
    }

    if (u->dest == bpf_htons(65535)) {
        __u32 k = 0, v = 1;
        bpf_map_update_elem(&m_kill, &k, &v, BPF_ANY);
        return XDP_DROP;
    }
    return XDP_PASS;
}

SEC("xdp")
int handle_ingress(struct xdp_md *ctx) {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    struct ethhdr *e = d;
    if ((void *)(e + 1) > de) return XDP_PASS;

    __u16 proto = e->h_proto;
    void *cur = e + 1;

    if (proto == bpf_htons(ETH_P_8021Q)) {
        struct { __be16 tci; __be16 p; } *v = cur;
        if ((void *)(v + 1) > de) return XDP_PASS;
        proto = v->p;
        cur += 4;
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cur;
        if ((void *)(ip + 1) > de) return XDP_PASS;
        if (ip->protocol == 47) { // GRE Tunnel Bypass
            cur += (ip->ihl * 4) + 4;
            ip = cur;
            if ((void *)(ip + 1) > de) return XDP_PASS;
        }
        if (ip->protocol == IPPROTO_UDP) return process_udp(de, ip, false);
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cur;
        if ((void *)(ip6 + 1) > de) return XDP_PASS;
        if (ip6->nexthdr == IPPROTO_UDP) return process_udp(de, ip6, true);
    }
    return XDP_PASS;
}

SEC("xdp")
int handle_egress(struct xdp_md *ctx) {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    struct ethhdr *e = d;
    if ((void *)(e + 1) > de) return XDP_PASS;

    if (e->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(e + 1);
        if ((void *)(ip + 1) > de) return XDP_PASS;
        __u64 *ts = bpf_map_lookup_elem(&m_v4, &ip->daddr);
        if (ts && (bpf_ktime_get_ns() - *ts < 3600000000000ULL)) return XDP_DROP;
    } else if (e->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(e + 1);
        if ((void *)(ip6 + 1) > de) return XDP_PASS;
        __u64 *ts = bpf_map_lookup_elem(&m_v6, &ip6->daddr);
        if (ts && (bpf_ktime_get_ns() - *ts < 3600000000000ULL)) return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
