# Fix for Compilation Error: Type Mismatch in getRemoteProcessHandle

## Problem
The compilation error occurred in `src/main.zig` at line 389 where there was a type mismatch:

```
expected type `**anyopaque` and found type `*?*anyopaque`
```

## Root Cause
1. `hProcess` was declared as `?HANDLE` (optional handle)
2. The function `getRemoteProcessHandle` expects `*windows.HANDLE` parameter
3. `windows.HANDLE` is `*anyopaque`, so `*windows.HANDLE` is `**anyopaque`
4. But `&hProcess` gives `*?*anyopaque` (pointer to optional pointer)

## Solution
1. Changed `hProcess` declaration from `?HANDLE` to `HANDLE`
2. Initialized it to `null` cast to `HANDLE`: `@ptrFromInt(0)`
3. Updated null checks throughout the code to handle non-optional HANDLE

## Changes Made

### Before (Problematic Code)
```zig
var hProcess: ?windows.HANDLE = null;
// ...
if (!getRemoteProcessHandle(&hProcess)) {  // Error: *?*anyopaque vs **anyopaque
    return;
}
// ...
if (hProcess) |handle| {  // Optional unwrapping
    // use handle
}
```

### After (Fixed Code)
```zig
var hProcess: windows.HANDLE = @ptrFromInt(0); // Initialize to null cast to HANDLE
// ...
if (!getRemoteProcessHandle(&hProcess)) {  // Now works: **anyopaque vs **anyopaque
    return;
}
// ...
if (@intFromPtr(hProcess) != 0) {  // Check if handle is valid
    // use hProcess directly
}
```

## Type Analysis
- `windows.HANDLE` = `*anyopaque`
- `?windows.HANDLE` = `?*anyopaque` (optional pointer)
- `*?windows.HANDLE` = `*?*anyopaque` (pointer to optional pointer)
- `*windows.HANDLE` = `**anyopaque` (pointer to pointer)

The fix ensures type compatibility by making the handle non-optional.