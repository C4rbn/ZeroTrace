pub const bpf_attr_load = extern struct {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32 = 0,
    log_buf: u64 = 0,
    kern_version: u32 = 0,
    prog_flags: u32 = 0,
};

pub const bpf_attr_link = extern struct {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32 = 0,
};

pub fn bpf_syscall(cmd: u32, attr: anytype, size: usize) i64 {
    return asm volatile ("syscall" : [ret] "={rax}" (-> i64) : [num] "{rax}" (@as(usize, 321)), [a1] "{rdi}" (@as(usize, cmd)), [a2] "{rsi}" (@intFromPtr(attr)), [a3] "{rdx}" (size) : "rcx", "r11", "memory");
}

pub fn mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: i32, off: usize) usize {
    return asm volatile ("syscall" : [ret] "={rax}" (-> usize) : [num] "{rax}" (@as(usize, 9)), [a1] "{rdi}" (addr), [a2] "{rsi}" (len), [a3] "{rdx}" (prot), [a4] "{r10}" (flags), [a5] "{r8}" (fd), [a6] "{r9}" (off) : "rcx", "r11", "memory");
}

pub fn clone(flags: usize, stack: usize) i64 {
    return asm volatile ("syscall" : [ret] "={rax}" (-> i64) : [num] "{rax}" (@as(usize, 56)), [a1] "{rdi}" (flags), [a2] "{rsi}" (stack) : "rcx", "r11", "memory");
}

pub fn nanosleep(sec: i64) i64 {
    const ts = struct { tv_sec: i64, tv_nsec: i64 }{ .tv_sec = sec, .tv_nsec = 0 };
    return asm volatile ("syscall" : [ret] "={rax}" (-> i64) : [num] "{rax}" (@as(usize, 35)), [a1] "{rdi}" (@intFromPtr(&ts)), [a2] "{rsi}" (0) : "rcx", "r11", "memory");
}

pub fn unlink(path: [*:0]const u8) i64 {
    return asm volatile ("syscall" : [ret] "={rax}" (-> i64) : [num] "{rax}" (@as(usize, 87)), [a1] "{rdi}" (@intFromPtr(path)) : "rcx", "r11", "memory");
}

pub fn exit(code: i32) noreturn {
    _ = asm volatile ("syscall" : : [num] "{rax}" (@as(usize, 60)), [a1] "{rdi}" (code) : "rcx", "r11", "memory");
    unreachable;
}
