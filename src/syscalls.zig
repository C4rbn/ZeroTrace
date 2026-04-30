const std = @import("std");

pub fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@as(usize, 157)), // __NR_prctl
          [arg1] "{rdi}" (@as(usize, @bitCast(@as(isize, option)))),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{r10}" (arg4),
          [arg5] "{r8}" (arg5),
        : "rcx", "r11", "memory"
    );
}

pub fn memfd_create(name: [*:0]const u8, flags: u32) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@as(usize, 319)), // __NR_memfd_create
          [arg1] "{rdi}" (@intFromPtr(name)),
          [arg2] "{rsi}" (@as(usize, flags)),
        : "rcx", "r11", "memory"
    );
}
