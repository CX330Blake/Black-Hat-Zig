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
