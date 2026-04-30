#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct a_v4 { __u32 a; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct a_v4);
    __type(value, __u64);
} m_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} m_kill SEC(".maps");

SEC("xdp")
int handle_ingress(struct xdp_md *ctx) {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    struct ethhdr *e = d;
    if ((void *)(e + 1) > de) return XDP_PASS;

    if (e->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(e + 1);
        if ((void *)(ip + 1) > de) return XDP_PASS;
        
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *u = (void *)ip + (ip->ihl * 4);
            if ((void *)(u + 1) > de) return XDP_PASS;

            if (u->dest == bpf_htons(65535)) {
                __u32 k = 0, v = 1;
                bpf_map_update_elem(&m_kill, &k, &v, BPF_ANY);
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
