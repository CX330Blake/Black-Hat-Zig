# Black-Hat-Zig

<p align="center">
  <img alt="GitHub Downloads (all assets, all releases)" src="https://img.shields.io/github/downloads/cx330blake/blake-hat-zig/total">
  <img alt="GitHub License" src="https://img.shields.io/github/license/CX330Blake/black-hat-zig">
  <img alt="GitHub top language" src="https://img.shields.io/github/languages/top/cx330blake/blake-hat-zig">
  <img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/cx330blake/blake-hat-zig">
  <img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/CX330Blake">
</p>

<p align="center">
  <a href="#intro">Intro</a> •
  <a href="#table-of-content">ToC</a> •
  <a href="#usage">Usage</a> •
  <a href="#contribution">Contribution</a> •
  <a href="#star-history">Star history</a>
</p>

<p height="300" align="center">
  <img src="./Black-Hat-Zig.png">
</p>

## Intro

Hello hackers. Hello maldevs. Hello reversers.

This project provides many malware techniques implementation using Zig since I'm a huge fan of it. But I'm still leaning, so please tell me if there's something wrong or can be optimized. It will be perfect if you want to create a PR for this project.

Okay, let's hack the planet!

## Disclaimer

This repository is provided for educational and research purposes only. The authors do not endorse or condone malicious use of the code or techniques demonstrated here. Use this project responsibly and always comply with applicable laws.

## Table of content

1. [Payload Placement](./Payload-Placement/)
    - [.data section](./Payload-Placement/dot_data_section/)
    - [.rdata section](./Payload-Placement/dot_rdata_section/)
    - [.text section](./Payload-Placement/dot_text_section/)
    - .rsrc section
2. [Payload Obfuscation](./Payload-Obfuscation/)

    - [IP Address Obfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/)
        - [IPv4 Obfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv4Fuscation/)
        - [IPv4 Deobfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv4Fuscation/)
        - [IPv6 Obfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv6Fuscation/)
        - [IPv6 Deobfuscation](./Payload-Obfuscation/IP-Address-Obfuscation/IPv6Deobfuscation/)
    - [MAC Address Obfuscation](./Payload-Obfuscation/MAC-Address-Obfuscation/)
        - [MAC Address Obfuscation](./Payload-Obfuscation/MAC-Address-Obfuscation/MACFuscation/)
        - [MAC Address Deobfuscation](./Payload-Obfuscation/MAC-Address-Obfuscation/MACDeobfuscation/)
    - [UUID Obfuscation](./Payload-Obfuscation/UUID-Obfuscation/)
        - [UUID Obfuscation](./Payload-Obfuscation/UUID-Obfuscation/UUIDFuscation/)
        - [UUID Deobfuscation](./Payload-Obfuscation/UUID-Obfuscation/UUIDDeobfuscation/)

3. [Payload Encryption](./Payload-Encryption/)
    - [XOR Encryption](./Payload-Encryption/XOR/)
    - [RC4 Encryption](./Payload-Encryption/RC4/)
    - [AES Encryption](./Payload-Encryption/AES/)

## Usage

You can check the codes inside each directory. Also, if the code uses Windows API, remember to compile it with `-Dtarget=x86_64-windows` flag. So following are commands to copy and paste.

**Normal binary**

```bash
zig build
```

**Binaries contain Window API**

```bash
zig build -Dtarget=x86_64-windows
```

## Contribution

This project is currently maintained by [@CX330Blake](https://github.com/CX330Blake). PRs are welcomed. Hope there's more people use Zig for malware developing so the ecosystem will be more mature.

See [LICENSE](./LICENSE) for license information.
