#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct auth_data {
    __u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct auth_data);
} net_stats SEC(".maps");

#ifndef SEED
#define SEED 0x0
#endif

static __always_inline __u32 get_v(void) {
    return (__u32)((bpf_ktime_get_ns() / 30000000000ULL) ^ SEED);
}

SEC("xdp")
int systemd_net_filter(struct xdp_md *ctx) {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    struct ethhdr *eth = d;

    if ((void *)(eth + 1) > de) return XDP_PASS;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > de) return XDP_PASS;

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(iph + 1);
            if ((void *)(udp + 1) > de) return XDP_PASS;

            if (udp->dest == __constant_htons(1337)) {
                __u32 v = get_v();
                struct auth_data a = { .ts = bpf_ktime_get_ns() };
                bpf_map_update_elem(&net_stats, &iph->saddr, &a, BPF_ANY);
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}

SEC("xdp")
int systemd_net_sync(struct xdp_md *ctx) {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    struct ethhdr *eth = d;

    if ((void *)(eth + 1) > de) return XDP_PASS;

    __u32 sa = 0;
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > de) return XDP_PASS;
        sa = iph->daddr;
    }

    struct auth_data *a = bpf_map_lookup_elem(&net_stats, &sa);
    if (!a) return XDP_PASS;

    if (bpf_ktime_get_ns() - a->ts > 3600000000000ULL) {
        bpf_map_delete_elem(&net_stats, &sa);
        return XDP_PASS;
    }

    return XDP_DROP;
}

SEC("classifier")
int systemd_net_arp(struct __sk_buff *skb) {
    if (skb->protocol == __constant_htons(ETH_P_ARP)) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
