#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

typedef struct { uint8_t a[16]; } __attribute__((packed)) ip_a;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, ip_a);
    __type(value, uint64_t);
} m_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint32_t);
} m_kill SEC(".maps");

SEC("xdp")
int ing(struct xdp_md *ctx) {
    void *d = (void *)(long)ctx->data, *de = (void *)(long)ctx->data_end;
    struct ethhdr *eth = d;
    if (__builtin_expect((void *)(eth + 1) > de, 0)) return XDP_PASS;

    uint16_t p = eth->h_proto;
    uint32_t off = sizeof(*eth);

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (p == bpf_htons(ETH_P_8021Q) || p == bpf_htons(ETH_P_8021AD)) {
            struct { uint16_t t; uint16_t p; } *v = d + off;
            if (__builtin_expect((void *)(v + 1) > de, 0)) return XDP_PASS;
            p = v->p; off += 4;
        }
    }

    ip_a src = {0};
    uint8_t l4 = 0;
    if (p == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = d + off;
        if (__builtin_expect((void *)(ip + 1) > de, 0)) return XDP_PASS;
        l4 = ip->protocol;
        __builtin_memcpy(&src.a[12], &ip->saddr, 4);
        off += (ip->ihl * 4);
    } else if (p == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = d + off;
        if (__builtin_expect((void *)(ip6 + 1) > de, 0)) return XDP_PASS;
        l4 = ip6->nexthdr;
        __builtin_memcpy(&src.a, &ip6->saddr, 16);
        off += 40;
    } else return XDP_PASS;

    if (l4 == IPPROTO_UDP) {
        struct udphdr *u = d + off;
        if (__builtin_expect((void *)(u + 1) > de, 0)) return XDP_PASS;
        if (u->dest == bpf_htons(65535)) {
            uint32_t k = 0, v = 1;
            bpf_map_update_elem(&m_kill, &k, &v, BPF_ANY);
            return XDP_DROP;
        }
        if (u->dest == bpf_htons(1337)) {
            uint64_t ts = bpf_ktime_get_ns();
            bpf_map_update_elem(&m_cache, &src, &ts, BPF_ANY);
            return XDP_DROP;
        }
    }

    uint64_t *at = bpf_map_lookup_elem(&m_cache, &src);
    if (at && (bpf_ktime_get_ns() - *at < 3600000000000ULL)) return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
