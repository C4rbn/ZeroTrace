#ifndef __BPF_HELPER_DEFS__
#define __BPF_HELPER_DEFS__

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) = (void *) 2;
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *) 5;
static int (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static int (*bpf_probe_read_kernel)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *) 113;

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#endif
