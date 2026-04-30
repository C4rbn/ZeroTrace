pub fn bpf_call(cmd: u32, attr: anytype, size: usize) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [number] "{rax}" (@as(usize, 321)),
          [arg1] "{rdi}" (@as(usize, cmd)),
          [arg2] "{rsi}" (@intFromPtr(attr)),
          [arg3] "{rdx}" (size),
        : "rcx", "r11", "memory"
    );
}

pub fn bpf_load(cmd: u32, blob: anytype, size: usize) i64 {
    return bpf_call(cmd, blob, size);
}

pub fn fork() i64 {
    return asm volatile ("syscall" : [ret] "={rax}" (-> i64) : [number] "{rax}" (@as(usize, 57)) : "rcx", "r11", "memory");
}

pub fn exit(code: i32) noreturn {
    _ = asm volatile ("syscall" : : [number] "{rax}" (@as(usize, 60)), [arg1] "{rdi}" (code) : "rcx", "r11", "memory");
    unreachable;
}

pub fn prctl(op: i32, a1: usize, a2: usize, a3: usize, a4: usize) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [number] "{rax}" (@as(usize, 157)),
          [arg1] "{rdi}" (@as(usize, @bitCast(@as(isize, op)))),
          [arg2] "{rsi}" (a1),
          [arg3] "{rdx}" (a2),
          [arg4] "{r10}" (a3),
          [arg5] "{r8}" (a4),
        : "rcx", "r11", "memory"
    );
}

pub fn unlink(path: [*:0]const u8) i64 {
    return asm volatile ("syscall" : [ret] "={rax}" (-> i64) : [number] "{rax}" (@as(usize, 87)), [arg1] "{rdi}" (@intFromPtr(path)) : "rcx", "r11", "memory");
}
