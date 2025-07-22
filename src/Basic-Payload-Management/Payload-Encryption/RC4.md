# RC4 Encryption

## TL;DR

[See the code example](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/src/Basic-Payload-Management/Payload-Encryption/RC4)

RC4 is a simple stream cipher that remains popular in malicious code because of
its small footprint and ease of implementation. In Windows, the undocumented
functions `SystemFunction032` and `SystemFunction033` can perform RC4
encryption. The sample code demonstrates encrypting a payload with one call and
decrypting it with another since RC4 is symmetric. Keeping shellcode encrypted
until execution helps avoid detection by static scanners that search for known
byte patterns.

## Using SystemFunction032

Preparing `USTRING` struct to represent the key and data buffers. `extern` is used so that its memory layout matches that of a corresponding C strcuct.
```zig title="main.zig"
const USTRING = extern struct {
    Length: DWORD,
    MaximumLength: DWORD,
    Buffer: PVOID,
};
```
`fnSystemFunction032` is a fucntion pointer to `SystemFunction032`
```zig title="main.zig"
const fnSystemFunction032 = fn (
    Data: *USTRING,
    Key: *USTRING,
) callconv(.C) NTSTATUS;
```

Helper function to call `SystemFunction032`
```zig title="main.zig"
/// Helper function that calls SystemFunction032 (RC4)
/// Reference: https://osandamalith.com/2022/11/10/encrypting-shellcode-using-systemfunction032-033/
pub fn rc4EncryptionViaSystemFunc032(
    rc4Key: []u8,
    payloadData: []u8,
) bool {
    // Prepare the USTRING structs
    var Data = USTRING{
        .Buffer = payloadData.ptr,
        .Length = @intCast(payloadData.len),
        .MaximumLength = @intCast(payloadData.len),
    };
    var Key = USTRING{
        .Buffer = rc4Key.ptr,
        .Length = @intCast(rc4Key.len),
        .MaximumLength = @intCast(rc4Key.len),
    };

    // Convert "Advapi32" to UTF-16LE for LoadLibraryW
    const advapi32_w = std.unicode.utf8ToUtf16LeStringLiteral("Advapi32");
    const advapi32 = kernel32.LoadLibraryW(advapi32_w);
    if (advapi32 == null) {
        std.debug.print("[!] LoadLibraryW failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }
    defer _ = kernel32.FreeLibrary(advapi32.?);

    const proc_addr = kernel32.GetProcAddress(advapi32.?, "SystemFunction032");
    if (proc_addr == null) {
        std.debug.print("[!] GetProcAddress failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }

    const SystemFunction032: *const fnSystemFunction032 = @ptrCast(proc_addr);

    const status: NTSTATUS = SystemFunction032(&Data, &Key);

    if (status != 0) {
        std.debug.print("[!] SystemFunction032 FAILED With Error: 0x{X:0>8}\n", .{status});
        return false;
    }
    return true;
}
```
Example usage:
```zig title="main.zig"
pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    // Example RC4 key and payload
    var key = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55 };
    var data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE };

    try stdout.print("[+] Original payload: {any}\n", .{data});
    try stdout.print("[+] RC4 key: {any}\n", .{key});

    // Encrypt (in-place)
    if (!rc4EncryptionViaSystemFunc032(key[0..], data[0..])) {
        try stdout.print("[+] Encryption failed!\n", .{});
        return;
    }
    try stdout.print("[+] Encrypted payload: {any}\n", .{data});

    // Decrypt (RC4 is symmetric, so call again with same key)
    if (!rc4EncryptionViaSystemFunc032(key[0..], data[0..])) {
        try stdout.print("[+] Decryption failed!\n", .{});
        return;
    }
    try stdout.print("[+] Decrypted payload: {any}\n", .{data});
}
```

## Using SystemFunction033

Preparing the `USTRING`
```zig title="main.zig"
const USTRING = extern struct {
    Length: DWORD,
    MaximumLength: DWORD,
    Buffer: PVOID,
};
```

`fnSystemFunction033` is the function pointer to `SystemFunction032`:
```zig title="main.zig"
const fnSystemFunction033 = fn (
    Data: *USTRING,
    Key: *USTRING,
) callconv(.C) NTSTATUS;
```

Helper function to call `SystemFunction033`:
```zig title="main.zig"
/// Helper function that calls SystemFunction033 (RC4)
/// Reference: https://osandamalith.com/2022/11/10/encrypting-shellcode-using-systemfunction032-033/
pub fn rc4EncryptionViaSystemFunc033(
    rc4Key: []u8,
    payloadData: []u8,
) bool {
    // Prepare the USTRING structs
    var Data = USTRING{
        .Buffer = payloadData.ptr,
        .Length = @intCast(payloadData.len),
        .MaximumLength = @intCast(payloadData.len),
    };
    var Key = USTRING{
        .Buffer = rc4Key.ptr,
        .Length = @intCast(rc4Key.len),
        .MaximumLength = @intCast(rc4Key.len),
    };

    // Convert "Advapi32" to UTF-16LE for LoadLibraryW
    const advapi32_w = std.unicode.utf8ToUtf16LeStringLiteral("Advapi32");
    const advapi32 = kernel32.LoadLibraryW(advapi32_w);
    if (advapi32 == null) {
        std.debug.print("[!] LoadLibraryW failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }
    defer _ = kernel32.FreeLibrary(advapi32.?);

    const proc_addr = kernel32.GetProcAddress(advapi32.?, "SystemFunction033");
    if (proc_addr == null) {
        std.debug.print("[!] GetProcAddress failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }

    const SystemFunction033: *const fnSystemFunction033 = @ptrCast(proc_addr);

    const status: NTSTATUS = SystemFunction033(&Data, &Key);

    if (status != 0) {
        std.debug.print("[!] SystemFunction033 FAILED With Error: 0x{X:0>8}\n", .{status});
        return false;
    }
    return true;
}
```

Example usage:
```zig title="main.zig"
pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    // Example RC4 key and payload
    var key = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55 };
    var data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE };

    try stdout.print("[+] Original payload: {any}\n", .{data});
    try stdout.print("[+] RC4 key: {any}\n", .{key});

    // Encrypt (in-place)
    if (!rc4EncryptionViaSystemFunc033(key[0..], data[0..])) {
        try stdout.print("[+] Encryption failed!\n", .{});
        return;
    }
    try stdout.print("[+] Encrypted payload: {any}\n", .{data});

    // Decrypt (RC4 is symmetric, so call again with same key)
    if (!rc4EncryptionViaSystemFunc033(key[0..], data[0..])) {
        try stdout.print("[+] Decryption failed!\n", .{});
        return;
    }
    try stdout.print("[+] Decrypted payload: {any}\n", .{data});
}
```
