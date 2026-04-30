pub const bpf_attr_load = extern struct { prog_type: u32, insn_cnt: u32, insns: u64, license: u64, log_level: u32 = 0, log_size: u32 = 0, log_buf: u64 = 0, kern_version: u32 = 0, prog_flags: u32 = 0, r: [80]u8 = [_]u8{0}**80 };
pub const bpf_attr_map = extern struct { map_type: u32, key_size: u32, value_size: u32, max_entries: u32, map_flags: u32 = 0, inner_map_fd: u32 = 0, numa_node: u32 = 0, map_name: [16]u8 = [_]u8{0}**16, map_ifindex: u32 = 0, btf_fd: u32 = 0, btf_key_type_id: u32 = 0, btf_value_type_id: u32 = 0 };
pub const bpf_attr_link = extern struct { prog_fd: u32, target_ifindex: u32, attach_type: u32, flags: u32 = 0, r: [48]u8 = [_]u8{0}**48 };
pub const bpf_attr_pin = extern struct { path: u64, fd: u32, flags: u32 = 0 };

pub fn bpf_syscall(cmd: u32, attr: anytype, size: usize) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 321)),
          [a1] "{rdi}" (@as(usize, cmd)),
          [a2] "{rsi}" (@intFromPtr(attr)),
          [a3] "{rdx}" (size)
        : "rcx", "r11", "memory"
    );
}

pub fn open(p: [*:0]const u8, f: i32) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 2)),
          [a1] "{rdi}" (@intFromPtr(p)),
          [a2] "{rsi}" (@as(usize, @bitCast(@as(isize, f))))
        : "rcx", "r11", "memory"
    );
}

pub fn read(fd: i32, b: []u8, l: usize) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 0)),
          [a1] "{rdi}" (@as(usize, @bitCast(@as(isize, fd)))),
          [a2] "{rsi}" (@intFromPtr(b.ptr)),
          [a3] "{rdx}" (l)
        : "rcx", "r11", "memory"
    );
}

pub fn close(fd: i32) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 3)),
          [a1] "{rdi}" (@as(usize, @bitCast(@as(isize, fd))))
        : "rcx", "r11", "memory"
    );
}

pub fn mmap(a: usize, l: usize, p: usize, f: usize, fd: i32, o: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize)
        : [num] "{rax}" (@as(usize, 9)),
          [a1] "{rdi}" (a),
          [a2] "{rsi}" (l),
          [a3] "{rdx}" (p),
          [a4] "{r10}" (f),
          [a5] "{r8}" (fd),
          [a6] "{r9}" (o)
        : "rcx", "r11", "memory"
    );
}

pub fn clone(f: usize, s: usize) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 56)),
          [a1] "{rdi}" (f),
          [a2] "{rsi}" (s)
        : "rcx", "r11", "memory"
    );
}

pub fn nanosleep(s: i64) i64 {
    const ts = struct { v: i64, n: i64 }{ .v = s, .n = 0 };
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 35)),
          [a1] "{rdi}" (@intFromPtr(&ts)),
          [a2] "{rsi}" (0)
        : "rcx", "r11", "memory"
    );
}

pub fn unlink(p: [*:0]const u8) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 87)),
          [a1] "{rdi}" (@intFromPtr(p))
        : "rcx", "r11", "memory"
    );
}

pub fn mkdir(p: [*:0]const u8, m: u32) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64)
        : [num] "{rax}" (@as(usize, 83)),
          [a1] "{rdi}" (@intFromPtr(p)),
          [a2] "{rsi}" (@as(usize, m))
        : "rcx", "r11", "memory"
    );
}

pub fn exit(c: i32) noreturn {
    asm volatile ("syscall"
        :
        : [num] "{rax}" (@as(usize, 60)),
          [a1] "{rdi}" (c)
        : "rcx", "r11", "memory"
    );
    unreachable;
}
