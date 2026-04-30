const std = @import("std");

pub fn bpf_call(cmd: u32, attr: anytype, size: usize) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [number] "{rax}" (@as(usize, 321)), // __NR_bpf
          [arg1] "{rdi}" (@as(usize, cmd)),
          [arg2] "{rsi}" (@intFromPtr(attr)),
          [arg3] "{rdx}" (size),
        : "rcx", "r11", "memory"
    );
}

pub fn bpf_obj_pin(fd: i32, path: [*:0]const u8) i64 {
    // Simplified struct for BPF_OBJ_PIN
    const attr = struct {
        pathname: u64,
        bpf_fd: u32,
    }{
        .pathname = @intFromPtr(path),
        .bpf_fd = @intCast(fd),
    };
    return bpf_call(6, &attr, @sizeOf(@TypeOf(attr)));
}
