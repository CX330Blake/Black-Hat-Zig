const std = @import("std");

/// Generates a UUID string from 16 raw bytes
fn generateUuid(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8, m: u8, n: u8, o: u8, p: u8, buffer: []u8) ![]const u8 {
    // In Zig, we can directly format the entire UUID in one go instead of
    // creating intermediate segments as in the C version
    return try std.fmt.bufPrint(buffer, "{X:0>2}{X:0>2}{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ d, c, b, a, f, e, h, g, i, j, k, l, m, n, o, p });
}

/// Generate the UUID output representation of the shellcode
fn generateUuidOutput(pShellcode: []const u8, writer: anytype) !bool {
    const shellcodeSize = pShellcode.len;

    // If the shellcode buffer is empty or the size is not a multiple of 16, exit
    if (shellcodeSize == 0 or shellcodeSize % 16 != 0) {
        return false;
    }

    try writer.print("const uuid_array = [_][*:0]const u8{{\n\t", .{});

    // Buffer to hold the UUID string (36 chars + null terminator)
    var uuidBuffer: [40]u8 = undefined;

    // Process the shellcode in groups of 16 bytes
    var counter: usize = 0;
    var i: usize = 0;

    while (i < shellcodeSize) {
        // Make sure we have 16 bytes available
        if (i + 15 >= shellcodeSize) break;

        counter += 1;

        // Generate the UUID from the current 16 bytes
        const uuid = try generateUuid(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7], pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11], pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15], &uuidBuffer);

        // Print the UUID
        if (i == shellcodeSize - 16) {
            // Last UUID
            try writer.print("\"{s}\"", .{uuid});
        } else {
            // Not the last one, add comma
            try writer.print("\"{s}\", ", .{uuid});
        }

        // Move to next group of 16 bytes
        i += 16;

        // Add a newline for formatting after every 3 UUIDs
        if (counter % 3 == 0 and i < shellcodeSize) {
            try writer.print("\n\t", .{});
        }
    }

    try writer.print("\n}};\n\n", .{});
    return true;
}

pub fn main() !void {
    // Example shellcode (must be a multiple of 16 bytes)
    const shellcode = [_]u8{
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, // Add more shellcode here if needed
    };

    // Use stdout as the writer
    const stdout = std.io.getStdOut().writer();

    std.debug.print("[+] Generating UUID representation for {} bytes of shellcode\n", .{shellcode.len});

    // Generate and print the UUID representation
    if (try generateUuidOutput(&shellcode, stdout)) {} else {
        std.debug.print("[!] Failed to generate UUID representation\n", .{});
    }
}
