# Before We Start

## Prerequisites

- Windows environment
  - The code can be compiled on Linux/MacOS, but still need a Windows environment to execute
- Zig >= 0.14.0
- ZYPE installed
  - ZYPE is a tool we will often used here. To install, please visit [ZYPE](https://github.com/cx330blake/zype)

## Compiling The Codes

The compilation is easy thanks to the good support for Zig's cross compilation. To build a Windows binary, we have three way to achieve it.

1. Add `-Dtarget` flag to the `zig build` or `zig build-exe` command during the compilation.
2. Simply run `zig-build` or `zig-build-exe` on a Windows machine.
3. Set the default target architecture and OS in the `build.zig`.

Here we'll use the third method to do this, so that no matter which OS you're using, you can simply run `zig build` to build the binary. For more details, this is the configuration I set for every projects that depend on Windows API.

```zig
const target = b.standardTargetOptions(.{ .default_target = .{
    .cpu_arch = .x86_64,
    .os_tag = .windows
}});
```

## Other Useful Tools

- [ZYRA: Your Runtime Armor](https://github.com/cx330blake/zyra)
  - An executable packer written in Zig
- [ZYPE: Your Payload Encryptor](https://github.com/cx330blake/zype)
  - MSFvenom shellcode got detected? ZYPE encrypt and obfuscate the shellcode for you!
