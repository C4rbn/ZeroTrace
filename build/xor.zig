const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = try init.minimal.args.iterateAllocator(allocator);

    _ = args.next(); // Skip binary name
    const path = args.next() orelse return;
    const seed_str = args.next() orelse return;
    
    const seed = try std.fmt.parseInt(u32, if (std.mem.startsWith(u8, seed_str, "0x")) seed_str[2..] else seed_str, 16);

    // Use direct POSIX calls to bypass the unstable std.fs abstractions
    const fd = try std.posix.open(path, .{ .ACCMODE = .RDWR }, 0);
    defer std.posix.close(fd);

    const stat = try std.posix.fstat(fd);
    const size: usize = @intCast(stat.size);
    const buf = try allocator.alloc(u8, size);
    
    _ = try std.posix.read(fd, buf);

    var k = seed;
    for (0..size) |i| {
        buf[i] ^= @intCast(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k +% 0x9E3779B9; 
    }

    try std.posix.lseek(fd, 0, std.posix.SEEK.SET);
    _ = try std.posix.write(fd, buf);
}
