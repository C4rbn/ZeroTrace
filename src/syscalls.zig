const std = @import("std");
const linux = std.os.linux;

// Industrial BPF Attribute Structures
pub const bpf_attr_load = extern struct {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32 = 0,
    log_size: u32 = 0,
    log_buf: u64 = 0,
    kern_version: u32 = 0,
    prog_flags: u32 = 0,
    r: [80]u8 = [_]u8{0} ** 80,
};

pub const bpf_attr_map = extern struct {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32 = 0,
    inner_map_fd: u32 = 0,
    numa_node: u32 = 0,
    map_name: [16]u8 = [_]u8{0} ** 16,
    map_ifindex: u32 = 0,
    btf_fd: u32 = 0,
    btf_key_type_id: u32 = 0,
    btf_value_type_id: u32 = 0,
};

pub const bpf_attr_link = extern struct {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32 = 0,
    r: [48]u8 = [_]u8{0} ** 48,
};

pub const bpf_attr_pin = extern struct {
    path: u64,
    fd: u32,
    flags: u32 = 0,
};

// Industrial Wrappers using the Zig Syscall Engine
pub fn bpf_syscall(cmd: u32, attr: anytype, size: usize) i64 {
    return @as(i64, @bitCast(linux.syscall3(.bpf, cmd, @intFromPtr(attr), size)));
}

pub fn open(p: [*:0]const u8, f: i32) i64 {
    return @as(i64, @bitCast(linux.syscall2(.open, @intFromPtr(p), @as(usize, @bitCast(@as(isize, f))))));
}

pub fn read(fd: i32, b: []u8, l: usize) i64 {
    return @as(i64, @bitCast(linux.syscall3(.read, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(b.ptr), l)));
}

pub fn close(fd: i32) i64 {
    return @as(i64, @bitCast(linux.syscall1(.close, @as(usize, @bitCast(@as(isize, fd))))));
}

pub fn mmap(a: usize, l: usize, p: usize, f: usize, fd: i32, o: usize) usize {
    return linux.syscall6(.mmap, a, l, p, f, @as(usize, @bitCast(@as(isize, fd))), o);
}

pub fn clone(f: usize, s: usize) i64 {
    return @as(i64, @bitCast(linux.syscall2(.clone, f, s)));
}

pub fn nanosleep(s: i64) i64 {
    const ts = linux.timespec{ .tv_sec = s, .tv_nsec = 0 };
    return @as(i64, @bitCast(linux.syscall2(.nanosleep, @intFromPtr(&ts), 0)));
}

pub fn unlink(p: [*:0]const u8) i64 {
    return @as(i64, @bitCast(linux.syscall1(.unlink, @intFromPtr(p))));
}

pub fn mkdir(p: [*:0]const u8, m: u32) i64 {
    return @as(i64, @bitCast(linux.syscall2(.mkdir, @intFromPtr(p), m)));
}

pub fn exit(c: i32) noreturn {
    _ = linux.syscall1(.exit, @as(usize, @bitCast(@as(isize, c))));
    unreachable;
}
