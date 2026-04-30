const std = @import("std");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try std.process.argsAlloc(arena.allocator());
    
    if (args.len < 3) {
        std.debug.print("Usage: xor <file> <hex_seed>\n", .{});
        std.process.exit(1);
    }

    const file_path = args[1];
    const seed_str = args[2];

    const file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
    defer file.close();
    
    const size = (try file.stat()).size;
    const buf = try arena.allocator().alloc(u8, size);
    _ = try file.readAll(buf);
    
    // Parse hex seed (e.g., 0xABC123)
    var k = try std.fmt.parseInt(u32, if (std.mem.startsWith(u8, seed_str, "0x")) seed_str[2..] else seed_str, 16);
    
    // XOR Loop
    for (0..buf.len) |i| {
        buf[i] ^= @intCast(k & 0xFF);
        k = (k >> 8) | (k << 24);
    }
    
    try file.seekTo(0);
    try file.writeAll(buf);
}
