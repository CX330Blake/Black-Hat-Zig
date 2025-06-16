# .rsrc Section

## Explanation

The `.rsrc` section of a PE file contains resources such as icons, images, and
version information. Malware sometimes hides shellcode within these resources
and extracts it at runtime, as the section is usually ignored by cursory code
scans. Although the example for this technique is not yet implemented in the
repository, the idea is to embed the payload as a resource and read it from the
`.rsrc` section when needed. See
<https://github.com/CX330Blake/Black-Hat-Zig/issues/5> for future updates.
