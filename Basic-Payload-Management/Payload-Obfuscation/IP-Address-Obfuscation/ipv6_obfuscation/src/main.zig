const std = @import("std");
const Allocator = std.mem.Allocator;

/// Function takes in 16 raw bytes and returns them in an IPv6 address string format
fn generateIpv6(allocator: Allocator, bytes: [16]u8) ![]u8 {
    // Each segment is 2 bytes (4 hex characters + colon)
    // Format as 8 segments of 2 bytes each with colons between them
    return try std.fmt.allocPrint(
        allocator,
        "{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}:{X:0>2}{X:0>2}",
        .{
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        },
    );
}

/// Generate the IPv6 output representation of the shellcode
/// Function requires a slice to the shellcode buffer
fn generateIpv6Output(allocator: Allocator, shellcode: []const u8) !bool {
    const stdout = std.io.getStdOut().writer();

    // If the shellcode buffer is empty or the size is not a multiple of 16, exit
    if (shellcode.len == 0 or shellcode.len % 16 != 0) {
        return false;
    }

    try stdout.print("const ipv6_array = [_][*:0]const u8{{\n    ", .{});

    // We will read one shellcode byte at a time, when the total is 16, begin generating the IPv6 address
    // The variable 'c' is used to store the number of bytes read. By default, starts at 16.
    var c: usize = 16;
    var counter: usize = 0;

    var i: usize = 0;
    while (i < shellcode.len) : (i += 1) {
        // Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the IPv6 address
        if (c == 16) {
            counter += 1;

            // Create a temporary array to hold the 16 bytes
            var temp_bytes: [16]u8 = undefined;
            @memcpy(temp_bytes[0..], shellcode[i..][0..16]);

            // Generating the IPv6 address from 16 bytes
            const ip = try generateIpv6(allocator, temp_bytes);
            defer allocator.free(ip);

            if (i == shellcode.len - 16) {
                // Printing the last IPv6 address
                try stdout.print("\"{s}\"", .{ip});
                break;
            } else {
                // Printing the IPv6 address
                try stdout.print("\"{s}\", ", .{ip});
            }

            c = 1;

            // Optional: To beautify the output on the console
            if (counter % 3 == 0) {
                try stdout.print("\n    ", .{});
            }
        } else {
            c += 1;
        }
    }

    try stdout.print("\n}};\n\n", .{});
    return true;
}

pub fn main() !void {
    // Create an arena allocator for efficient memory management
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    // Example shellcode (must be a multiple of 16 bytes)
    const shellcode = [_]u8{
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, // Add more shellcode here if needed
    };

    // Generate and print the IPv6 representation
    _ = try generateIpv6Output(allocator, &shellcode);
}
