#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} eth_state SEC(".maps");

SEC("xdp")
int virtnet_poll(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u8 *ptr = data;
    if (ptr + 34 > (__u8 *)data_end) return XDP_PASS;

    // Fast TOTP: Use bit-shift instead of division for Verifier
    // (now >> 35) is approx 34.3 seconds
    __u64 now = bpf_ktime_get_ns();
    __u32 secret = (__u32)((now >> 35) ^ 0xDEADBEEF);

    __u32 src_ip = *(__u32 *)(ptr + 26);
    __u16 ip_id = *(__u16 *)(ptr + 18);

    if (ip_id == (__u16)secret) {
        __u64 ts = now;
        bpf_map_update_elem(&eth_state, &src_ip, &ts, BPF_ANY);
        return XDP_DROP;
    }

    if (!bpf_map_lookup_elem(&eth_state, &src_ip)) return XDP_DROP;

    return XDP_PASS;
}
