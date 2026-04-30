const std = @import("std");
const linux = std.os.linux;

/// Direct wrapper for the BPF syscall
/// cmd: The BPF command (e.g., BPF_PROG_LOAD)
/// attr: Pointer to the bpf_attr union
/// size: Size of the attr structure
pub fn bpf(cmd: u32, attr: *anyopaque, size: u32) usize {
    return linux.syscall3(.bpf, cmd, @intFromPtr(attr), size);
}

/// Direct wrapper for memfd_create
/// name: The name for the anonymous file (visible in /proc/self/fd/)
/// flags: MFD_CLOEXEC, etc.
pub fn memfd_create(name: [*:0]const u8, flags: u32) usize {
    return linux.syscall2(.memfd_create, @intFromPtr(name), flags);
}

/// prctl wrapper for process masking
pub fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return linux.syscall5(.prctl, @as(usize, @bitCast(@as(isize, option))), arg2, arg3, arg4, arg5);
}

// BPF Command Constants
pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

// io_uring Constants for persistence logic
pub const IORING_SETUP_SQPOLL: u32 = (1 << 1);
