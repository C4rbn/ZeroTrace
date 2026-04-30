#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8[16]);
    __type(value, __u64);
} eth_state SEC(".maps");

SEC("xdp")
int virtnet_poll(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u8 *ptr = data;
    if (ptr + 14 > (__u8 *)data_end) return XDP_PASS;

    __u16 h_proto = *(__u16 *)(ptr + 12);
    __u8 addr[16] = {0};
    __u16 pkt_id = 0;
    __u8 is_ipv6 = 0;

    if (h_proto == 0x0008) { 
        if (ptr + 34 > (__u8 *)data_end) return XDP_PASS;
        *(__u32 *)&addr[0] = *(__u32 *)(ptr + 26);
        pkt_id = *(__u16 *)(ptr + 18);
    } else if (h_proto == 0xDD86) { 
        if (ptr + 54 > (__u8 *)data_end) return XDP_PASS;
        for(int i=0; i<16; i++) addr[i] = *(ptr + 22 + i);
        pkt_id = *(__u16 *)(ptr + 4); 
        is_ipv6 = 1;
    } else {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 secret = (__u32)((now >> 35) ^ SEED);

    if (pkt_id == (__u16)secret) {
        __u64 ts = now;
        bpf_map_update_elem(&eth_state, &addr, &ts, BPF_ANY);
        return XDP_DROP;
    }

    if (!bpf_map_lookup_elem(&eth_state, &addr)) return XDP_DROP;

    return XDP_PASS;
}
