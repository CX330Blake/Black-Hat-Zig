const std = @import("std");

/// This is the first approach to encrypt the payload.
/// We add the index "i" to each iteration to make the encryption
/// more complicated.
fn xorWithKeyAndIndex(payload: []u8, key: u8) void {
    for (payload, 0..) |*byte, i| {
        // Truncate i to u8 (i mod 256), then do wrapping add with key (overflow in the sum),
        // finally XOR the result with the payload byte.
        byte.* = byte.* ^ (key +% @as(u8, @truncate(i)));
    }
}

/// This is the second approach to encrypt the payload.
/// We use a multi-bytes key and iterate each byte as different
/// key in each iteration.
fn xorWithMultiBytesKey(payload: []u8, key: []const u8) void {
    const key_len = key.len;
    if (key_len == 0) @panic("Key length must be greater than 0"); // Division by zero

    var j: usize = 0;
    for (payload) |*byte| {
        byte.* = byte.* ^ key[j];
        j += 1;
        if (j >= key_len) {
            j = 0;
        }
    }
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    // Test xorByIKeys
    var payload1 = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50 };
    const key1: u8 = 0xAA;
    try stdout.print("[+] Original payload1: {any}\n", .{payload1});
    xorWithKeyAndIndex(payload1[0..], key1);
    try stdout.print("[+] After xorByIKeys with key {X}: {any}\n", .{ key1, payload1 });
    // To show a reversible operation:
    xorWithKeyAndIndex(payload1[0..], key1);
    try stdout.print("[+] Restored payload1: {any}\n\n", .{payload1});

    // Test xorByInputKey
    var payload2 = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const key2 = [_]u8{ 0x10, 0x20, 0x30 };
    try stdout.print("[+] Original payload2: {any}\n", .{payload2});
    xorWithMultiBytesKey(payload2[0..], key2[0..]);
    try stdout.print("[+] After xorByInputKey with key {any}: {any}\n", .{ key2, payload2 });
    // Reversible operation:
    xorWithMultiBytesKey(payload2[0..], key2[0..]);
    try stdout.print("[+] Restored payload2: {any}\n", .{payload2});
}
