const std = @import("std");
const Allocator = std.mem.Allocator;

// Function takes in 4 raw bytes and returns them in an IPv4 string format
fn generateIpv4(allocator: Allocator, a: u8, b: u8, c: u8, d: u8) ![]u8 {
    // Creating the IPv4 address string
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ a, b, c, d });
}

/// Generate the IPv4 output representation of the shellcode
/// Function requires an allocator and shellcode as the input
fn generateIpv4Output(allocator: Allocator, shellcode: []const u8) !bool {
    const stdout = std.io.getStdOut().writer();

    // If the shellcode buffer is empty or the size is not a multiple of 4, exit
    if (shellcode.len == 0 or shellcode.len % 4 != 0) {
        return false;
    }

    try stdout.print("const ipv4_array = [_][*:0]const u8{{\n\t", .{});

    // We will read one shellcode byte at a time, when the total is 4, begin generating the IPv4 address
    // The variable 'c' is used to store the number of bytes read. By default, starts at 4.
    var c: usize = 4;
    var counter: usize = 0;

    var i: usize = 0;
    while (i < shellcode.len) : (i += 1) {
        // Track the number of bytes read and when they reach 4 we enter this if statement to begin generating the IPv4 address
        if (c == 4) {
            counter += 1;

            // Generating the IPv4 address from 4 bytes which begin at i until [i + 3]
            const ip = try generateIpv4(allocator, shellcode[i], shellcode[i + 1], shellcode[i + 2], shellcode[i + 3]);
            defer allocator.free(ip); // Free the allocated string when done

            if (i == shellcode.len - 4) {
                // Printing the last IPv4 address
                try stdout.print("\"{s}\"", .{ip});
                break;
            } else {
                // Printing the IPv4 address
                try stdout.print("\"{s}\", ", .{ip});
            }

            c = 1;

            // Optional: To beautify the output on the console
            if (counter % 8 == 0) {
                try stdout.print("\n\t", .{});
            }
        } else {
            c += 1;
        }
    }

    try stdout.print("\n}};\n\n", .{});
    return true;
}

pub fn main() !void {
    // Create an arena allocator that frees all allocations at once at the end
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    // Example shellcode (must be a multiple of 4 bytes)
    const shellcode = [_]u8{
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, // Add more shellcode here if needed
    };

    // Generate and print the IPv4 representation
    _ = try generateIpv4Output(allocator, &shellcode);
}
