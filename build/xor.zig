const std = @import("std");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);

    const path = args[1];
    const seed_str = args[2];
    
    const seed = try std.fmt.parseInt(u32, if (std.mem.startsWith(u8, seed_str, "0x")) seed_str[2..] else seed_str, 16);

    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();

    const size = (try file.stat()).size;
    const buf = try allocator.alloc(u8, size);
    const read_len = try file.readAll(buf);

    var k = seed;
    for (0..read_len) |i| {
        buf[i] ^= @intCast(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k +% 0x9E3779B9; 
    }

    try file.seekTo(0);
    try file.writeAll(buf);
}
