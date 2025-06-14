const std = @import("std");
const win = std.os.windows;
const kernel32 = win.kernel32;
const time = std.time;
const print = std.debug.print;

const c = @cImport({
    @cInclude("./aes.h");
});

const BOOL = i32;
const PBYTE = [*]u8;
const SIZE_T = usize;
const BYTE = u8;

const TRUE = 1;
const FALSE = 0;
const KEYSIZE = 32;
const IVSIZE = 16;

// Zig-based random number generator (replacing srand/rand)
var rng_state: std.Random.DefaultPrng = undefined;
var rng_initialized: bool = false;

fn initRng() void {
    if (!rng_initialized) {
        rng_state = std.Random.DefaultPrng.init(@as(u64, @bitCast(time.milliTimestamp())));
        rng_initialized = true;
    }
}

fn seedRng(seed: u64) void {
    rng_state = std.Random.DefaultPrng.init(seed);
    rng_initialized = true;
}

fn randByte() u8 {
    if (!rng_initialized) initRng();
    return rng_state.random().int(u8);
}

// Generate random bytes using Zig's RNG
fn generateRandomBytes(buffer: [*]u8, size: usize) void {
    var i: usize = 0;
    while (i < size) : (i += 1) {
        buffer[i] = randByte();
    }
}

// Print hex data
fn printHexData(name: []const u8, data: [*]const u8, size: usize) void {
    print("const {s} = [_]u8{{\n\t", .{name});
    var i: usize = 0;
    while (i < size) : (i += 1) {
        if (i % 16 == 0 and i != 0) print("\n\t", .{});
        if (i < size - 1) {
            print("0x{X:0>2}, ", .{data[i]});
        } else {
            print("0x{X:0>2} ", .{data[i]});
        }
    }
    print("\n}};\n\n", .{});
}

// Padding buffer function
fn padBuffer(
    input_buffer: [*]const u8,
    input_buffer_size: SIZE_T,
    output_padded_buffer: *?[*]u8,
    output_padded_size: *SIZE_T,
) BOOL {
    var padded_buffer: ?[*]u8 = null;
    var padded_size: SIZE_T = 0;

    // Calculate the nearest number that is multiple of 16
    padded_size = input_buffer_size + 16 - (input_buffer_size % 16);

    // Allocating buffer of size "padded_size"
    padded_buffer = @ptrCast(kernel32.HeapAlloc(kernel32.GetProcessHeap().?, 0, padded_size));
    if (padded_buffer == null) {
        return FALSE;
    }

    // Zero the allocated buffer
    @memset(padded_buffer.?[0..padded_size], 0);

    // Copy old buffer to new padded buffer
    @memcpy(padded_buffer.?[0..input_buffer_size], input_buffer[0..input_buffer_size]);

    // Save results
    output_padded_buffer.* = padded_buffer;
    output_padded_size.* = padded_size;

    return TRUE;
}

// Encryption example (equivalent to first C program)
fn aesEncrypt() void {
    print("=== ENCRYPTION EXAMPLE ===\n\n", .{});

    // "this is plane text sting, we'll try to encrypt... lets hope everythign go well :)" in hex
    var data = [_]u8{ 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x67, 0x69, 0x76, 0x65, 0x20, 0x42, 0x6c, 0x61, 0x63, 0x6b, 0x2d, 0x48, 0x61, 0x74, 0x2d, 0x5a, 0x69, 0x67, 0x20, 0x61, 0x20, 0x73, 0x74, 0x61, 0x72, 0x21 };

    // Struct needed for Tiny-AES library
    var ctx: c.struct_AES_ctx = undefined;

    var p_key: [KEYSIZE]BYTE = undefined;
    var p_iv: [IVSIZE]BYTE = undefined;

    // Seed random number generator using Zig RNG
    seedRng(@as(u64, @bitCast(time.timestamp())));
    generateRandomBytes(&p_key, KEYSIZE);

    // Use first byte of key for additional randomness in IV generation
    seedRng(@as(u64, @bitCast(time.timestamp())) ^ p_key[0]);
    generateRandomBytes(&p_iv, IVSIZE);

    // Print key and IV
    printHexData("pKey", &p_key, KEYSIZE);
    printHexData("pIv", &p_iv, IVSIZE);

    // Initialize Tiny-AES library
    c.AES_init_ctx_iv(&ctx, &p_key, &p_iv);

    // Variables for padded buffer
    var padded_buffer: ?[*]u8 = null;
    var padded_size: SIZE_T = 0;

    // Check if padding is required
    if (data.len % 16 != 0) {
        if (padBuffer(&data, data.len, &padded_buffer, &padded_size) == TRUE) {
            // Encrypt the padded buffer
            c.AES_CBC_encrypt_buffer(&ctx, padded_buffer.?, @intCast(padded_size));
            // Print encrypted buffer
            printHexData("CipherText", padded_buffer.?, padded_size);
        }
    } else {
        // No padding required, encrypt data directly
        c.AES_CBC_encrypt_buffer(&ctx, &data, @intCast(data.len));
        printHexData("CipherText", &data, data.len);
    }

    // Free padded buffer if allocated
    if (padded_buffer != null) {
        _ = kernel32.HeapFree(kernel32.GetProcessHeap().?, 0, padded_buffer.?);
    }
}

// Decryption example (equivalent to second C program)
fn aesDecrypt() void {
    print("=== DECRYPTION EXAMPLE ===\n\n", .{});

    // Key
    const p_key = [_]u8{ 0xFD, 0x73, 0x3E, 0x2F, 0x9D, 0x1A, 0x5E, 0x17, 0x4A, 0xD4, 0x8A, 0x14, 0x9E, 0xE6, 0x99, 0x0C, 0x5E, 0x88, 0xCC, 0x92, 0xB4, 0x7E, 0x88, 0x9D, 0x03, 0x47, 0x60, 0x1A, 0x2F, 0xF6, 0xDB, 0x22 };
    // IV
    const p_iv = [_]u8{ 0x57, 0x0C, 0x92, 0xE0, 0xE0, 0xB9, 0x52, 0x1A, 0xE7, 0x70, 0x6A, 0xE8, 0x61, 0xF3, 0xB0, 0x52 };
    // Encrypted data (multiples of 16 bytes)
    var cipher_text = [_]u8{ 0xBA, 0x94, 0x8F, 0xDD, 0x42, 0xB0, 0x67, 0xB4, 0x32, 0x05, 0x08, 0x09, 0x13, 0x92, 0x9E, 0x4D, 0xF4, 0xF6, 0x38, 0xA1, 0x9A, 0x07, 0x55, 0x4B, 0xE7, 0xF3, 0x72, 0x86, 0x2D, 0xEB, 0x7E, 0xA8, 0xC7, 0xD2, 0xD6, 0xC9, 0xE5, 0x7A, 0x63, 0x09, 0x64, 0xF1, 0x16, 0xD0, 0xFB, 0x9C, 0x89, 0xFA, 0xBA, 0x45, 0x50, 0xAC, 0xE4, 0x94, 0x64, 0x4F, 0x49, 0x11, 0x31, 0x76, 0x48, 0x6E, 0x2D, 0x03 };
    // Struct needed for Tiny-AES library
    var ctx: c.struct_AES_ctx = undefined;

    // Initialize Tiny-AES library
    c.AES_init_ctx_iv(&ctx, &p_key, &p_iv);

    print("Original key:\n", .{});
    printHexData("pKey", &p_key, p_key.len);
    print("Original IV:\n", .{});
    printHexData("pIv", &p_iv, p_iv.len);
    print("Original ciphertext:\n", .{});
    printHexData("CipherText", &cipher_text, cipher_text.len);

    // Decrypt
    c.AES_CBC_decrypt_buffer(&ctx, &cipher_text, @intCast(cipher_text.len));

    // Print decrypted buffer
    print("Decrypted data:\n", .{});
    printHexData("PlainText", &cipher_text, cipher_text.len);

    // Print as string (find null terminator or use full length)
    var str_len: usize = 0;
    for (cipher_text, 0..) |byte, i| {
        if (byte == 0) {
            str_len = i;
            break;
        }
    }
    if (str_len == 0) str_len = cipher_text.len;

    print("Data: {s}\n", .{cipher_text[0..str_len]});
}

pub fn main() !void {
    print("Tiny-AES Zig Implementation\n", .{});
    print("===========================\n\n", .{});

    // Encryption example
    aesEncrypt();

    print("\n", .{});

    // Decryption example
    aesDecrypt();

    return;
}
