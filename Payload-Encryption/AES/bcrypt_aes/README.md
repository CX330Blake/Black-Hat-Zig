# AES with bCrypt.h

> [!IMPORTANT]
> This includes Windows API so it should be run on Windows

Using bCrypt.h to do the AES encryption will expose the Windows API in the import address table (IAT), which may be blocked by some security solutions.

Build this example on Windows with `zig build`.
