const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;

// Embed the payload directly - let the linker handle section placement
const payload_data = @embedFile("calc.ico");

// Create a proper Windows-compatible embedded payload
const embedded_payload: [payload_data.len]u8 = payload_data.*;

/// Windows-compatible wait function
fn waitForEnter(message: []const u8) void {
    print("{s}", .{message});
    var buffer: [1]u8 = undefined;
    _ = std.io.getStdIn().reader().read(buffer[0..]) catch {};
}

pub fn main() !void {
    // Access the embedded payload
    const p_payload_address = &embedded_payload;
    const s_payload_size = embedded_payload.len;

    print("[+] Successfully accessed embedded payload!\n", .{});
    print("[i] Payload Address: 0x{X}\n", .{@intFromPtr(p_payload_address)});
    print("[i] Payload Size: {d} bytes\n", .{s_payload_size});
    print("[i] Payload is embedded in executable\n", .{});
    print("[i] Method: @embedFile (compile-time embedding)\n", .{});

    // Show first 16 bytes for verification
    print("[i] First 16 bytes: ", .{});
    const preview_size = @min(16, embedded_payload.len);
    for (embedded_payload[0..preview_size]) |byte| {
        print("{X:0>2} ", .{byte});
    }
    print("\n", .{});

    // Demonstrate payload is accessible and writable
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const writable_copy = try allocator.alloc(u8, s_payload_size);
    @memcpy(writable_copy, &embedded_payload);

    print("\n[i] Created writable copy at: 0x{X}\n", .{@intFromPtr(writable_copy.ptr)});
    print("[i] Ready for decryption, unpacking, or execution...\n", .{});

    // Test modification
    const original_byte = writable_copy[0];
    writable_copy[0] = 0xFF;
    print("[i] Test modification: First byte changed from 0x{X:0>2} to 0x{X:0>2}\n", .{ original_byte, writable_copy[0] });
    writable_copy[0] = original_byte;
    print("[i] First byte restored to original value\n", .{});

    print("\n", .{});
    print("[+] Payload processing completed successfully!\n", .{});
    print("[i] Embedded payload is ready for malware research\n", .{});
    print("\n", .{});

    waitForEnter("[#] Press <Enter> To Exit ...\n");
}
