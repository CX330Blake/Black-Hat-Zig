# Payload Placement

Examples showing how to embed a payload into various PE sections. Each subdirectory demonstrates placing shellcode in a different section. Build any of them with `zig build` to generate the example binary.

- `dot_data_section` – place shellcode in the `.data` section.
- `dot_rdata_section` – place shellcode in the `.rdata` section.
- `dot_text_section` – place shellcode in the executable `.text` section.
- `dot_rsrc_section` – embed data in the `.rsrc` section using a resource file.
