# AES with tiny-AES-c project

> [!IMPORTANT]
> This includes Windows API so it should be run on Windows

The original project is [here](https://github.com/kokke/tiny-AES-c).

To use this, you should have `aes.h` or `aes.hpp` inside your project folder, also, add the `aes.c` to your project.

And using this to implement the AES will cause the following disadvantage:

1. This library didn't support for padding, so you need to implement the padding algorithm on your own or make sure your payload is divisible by 16.
2. The **sbox** in the library might be signatured by security solutions. The **sbox** arrays are used in the AES encryption/decryption process, so they must be included in the code. We do have some way to evade the signature detection, for example, we can XOR these values in sbox and XOR it again before we using calling the initialize function (`AES_init_ctx_iv`).
