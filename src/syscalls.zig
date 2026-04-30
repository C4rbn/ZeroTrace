const std = @import("std");

pub const linux_dirent = struct {
    d_ino: u64,
    d_off: u64,
    d_reclen: u16,
    d_name: [256]u8,
};

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
};

pub const bpf_attr_map_op = extern struct {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64 = 0,
};

pub const bpf_attr_link = extern struct {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
};

pub fn syscall1(num: usize, arg1: usize) usize {
    return asm volatile ("syscall" : [ret] "={rax}" (-> usize) : [num] "{rax}" (num), [arg1] "{rdi}" (arg1) : "rcx", "r11", "memory");
}

pub fn syscall3(num: usize, a1: usize, a2: usize, a3: usize) usize {
    return asm volatile ("syscall" : [ret] "={rax}" (-> usize) : [num] "{rax}" (num), [a1] "{rdi}" (a1), [a2] "{rsi}" (a2), [a3] "{rdx}" (a3) : "rcx", "r11", "memory");
}

pub fn bpf_syscall(cmd: u32, attr: *const anyopaque, size: u32) i64 {
    return @intCast(syscall3(321, @intCast(cmd), @intFromPtr(attr), @intCast(size)));
}

pub fn open(path: [*:0]const u8, flags: i32) i32 { return @intCast(syscall3(2, @intFromPtr(path), @intCast(flags), 0)); }
pub fn read(fd: i32, buf: [*]u8, len: usize) usize { return syscall3(0, @intCast(fd), @intFromPtr(buf), len); }
pub fn close(fd: i32) void { _ = syscall1(3, @intCast(fd)); }
pub fn mkdir(path: [*:0]const u8, mode: u32) i32 { return @intCast(syscall3(83, @intFromPtr(path), @intCast(mode), 0)); }
pub fn unlink(path: [*:0]const u8) i32 { return @intCast(syscall1(87, @intFromPtr(path))); }
pub fn exit(code: u32) noreturn { _ = syscall1(60, @intCast(code)); while (true) {} }

pub fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i64 {
    return @intCast(asm volatile ("syscall" : [ret] "={rax}" (-> usize) : [num] "{rax}" (157), [a1] "{rdi}" (@intCast(option)), [a2] "{rsi}" (arg2), [a3] "{rdx}" (arg3), [a4] "{r10}" (arg4), [a5] "{r8}" (arg5) : "rcx", "r11", "memory"));
}

pub fn mount(src: ?[*]const u8, tgt: [*]const u8, typ: ?[*]const u8, fl: usize, data: ?*anyopaque) i64 {
    return @intCast(asm volatile ("syscall" : [ret] "={rax}" (-> usize) : [num] "{rax}" (165), [a1] "{rdi}" (@intFromPtr(src)), [a2] "{rsi}" (@intFromPtr(tgt)), [a3] "{rdx}" (@intFromPtr(typ)), [a4] "{r10}" (fl), [a5] "{r8}" (@intFromPtr(data)) : "rcx", "r11", "memory"));
}

pub fn utimensat(dirfd: i32, path: [*:0]const u8, times: *const [4]i64, flags: i32) i64 {
    return @intCast(asm volatile ("syscall" : [ret] "={rax}" (-> usize) : [num] "{rax}" (280), [a1] "{rdi}" (@intCast(dirfd)), [a2] "{rsi}" (@intFromPtr(path)), [a3] "{rdx}" (@intFromPtr(times)), [a4] "{r10}" (@intCast(flags)) : "rcx", "r11", "memory"));
}

pub fn getdents(fd: i32, buf: [*]u8, count: usize) usize {
    return syscall3(78, @intCast(fd), @intFromPtr(buf), count);
}

pub fn nanosleep(seconds: i64) void {
    const ts = [2]i64{ seconds, 0 };
    _ = syscall3(35, @intFromPtr(&ts), 0, 0);
}
