# AES Encryption

## TL;DR

[See the code example](https://github.com/CX330Blake/Black-Hat-Zig/tree/main/src/Basic-Payload-Management/Payload-Encryption/AES)

Advanced Encryption Standard (AES) is a widely used symmetric cipher. Malware
often encrypts embedded payloads with AES so that static scanners cannot easily
identify the malicious code. This chapter demonstrates multiple ways to perform
AES encryption in Zig, including using Windows' `bcrypt` API and simple
implementations. The encrypted payload is decrypted in memory right before
execution, keeping the malicious bytes hidden on disk and complicating analysis.

## Using bcrypt.h

[bcrypt.h header - MSDN](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/)

```zig title="main.zig"
const std = @import("std");
const win = std.os.windows;
const kernel32 = win.kernel32;

const KEY_SIZE = 32;
const IV_SIZE = 16;

const DWORD = u32;
const BOOL = i32;
const PBYTE = [*]u8;
const PVOID = ?*anyopaque;
const ULONG = u32;
const NTSTATUS = i32;

const BCRYPT_BLOCK_PADDING = 0x00000001;
const STATUS_SUCCESS: NTSTATUS = 0;

const BCRYPT_AES_ALGORITHM = std.unicode.utf8ToUtf16LeStringLiteral("AES");
const BCRYPT_CHAINING_MODE = std.unicode.utf8ToUtf16LeStringLiteral("ChainingMode");
const BCRYPT_CHAIN_MODE_CBC = std.unicode.utf8ToUtf16LeStringLiteral("ChainingModeCBC");

const AES = extern struct {
    pPlainText: ?PBYTE,
    dwPlainSize: DWORD,
    pCipherText: ?PBYTE,
    dwCipherSize: DWORD,
    pKey: ?PBYTE,
    pIv: ?PBYTE,
};

extern "bcrypt" fn BCryptOpenAlgorithmProvider(
    phAlgorithm: *?*anyopaque,
    pszAlgId: [*:0]const u16,
    pszImplementation: ?[*:0]const u16,
    dwFlags: ULONG,
) callconv(.C) NTSTATUS;

extern "bcrypt" fn BCryptCloseAlgorithmProvider(
    hAlgorithm: ?*anyopaque,
    dwFlags: ULONG,
) callconv(.C) NTSTATUS;

extern "bcrypt" fn BCryptGetProperty(
    hObject: ?*anyopaque,
    pszProperty: [*:0]const u16,
    pbOutput: PBYTE,
    cbOutput: ULONG,
    pcbResult: *ULONG,
    dwFlags: ULONG,
) callconv(.C) NTSTATUS;

extern "bcrypt" fn BCryptSetProperty(
    hObject: ?*anyopaque,
    pszProperty: [*:0]const u16,
    pbInput: PBYTE,
    cbInput: ULONG,
    dwFlags: ULONG,
) callconv(.C) NTSTATUS;

extern "bcrypt" fn BCryptGenerateSymmetricKey(
    hAlgorithm: ?*anyopaque,
    phKey: *?*anyopaque,
    pbKeyObject: PBYTE,
    cbKeyObject: ULONG,
    pbSecret: PBYTE,
    cbSecret: ULONG,
    dwFlags: ULONG,
) callconv(.C) NTSTATUS;

extern "bcrypt" fn BCryptDestroyKey(hKey: ?*anyopaque) callconv(.C) NTSTATUS;

extern "bcrypt" fn BCryptEncrypt(
    hKey: ?*anyopaque,
    pbInput: [*]u8,
    cbInput: ULONG,
    pPaddingInfo: ?*anyopaque,
    pbIV: [*]u8,
    cbIV: ULONG,
    pbOutput: ?[*]u8,
    cbOutput: ULONG,
    pcbResult: *ULONG,
    dwFlags: ULONG,
) callconv(.C) NTSTATUS;

extern "bcrypt" fn BCryptDecrypt(
    hKey: ?*anyopaque,
    pbInput: [*]u8,
    cbInput: ULONG,
    pPaddingInfo: ?*anyopaque,
    pbIV: [*]u8,
    cbIV: ULONG,
    pbOutput: ?[*]u8,
    cbOutput: ULONG,
    pcbResult: *ULONG,
    dwFlags: ULONG,
) callconv(.C) NTSTATUS;

// Generate random bytes
fn generateRandomBytes(buf: []u8) void {
    var prng = std.Random.DefaultPrng.init(@as(u64, @bitCast(std.time.milliTimestamp())));
    const rand = prng.random();
    for (buf) |*b| b.* = rand.int(u8);
}

// Print a buffer as a C hex array
fn printHexData(name: []const u8, data: []const u8) void {
    std.debug.print("const {s} = [_]u8{{", .{name});
    var i: usize = 0;
    for (data) |b| {
        if (i % 16 == 0) std.debug.print("\n\t", .{});
        if (i < data.len - 1) {
            std.debug.print("0x{X:0>2}, ", .{b});
        } else {
            std.debug.print("0x{X:0>2} ", .{b});
        }
        i += 1;
    }
    std.debug.print("\n}};\n\n\n", .{});
}

fn ntSuccess(status: NTSTATUS) bool {
    return status >= 0;
}

// Remove PKCS#7 padding from decrypted data
fn removePkcs7Padding(data: []u8) ?[]u8 {
    if (data.len == 0) return null;

    const padding_length = data[data.len - 1];

    // Validate padding length
    if (padding_length == 0 or padding_length > 16 or padding_length > data.len) {
        return null;
    }

    // Validate all padding bytes are the same
    const start_index = data.len - padding_length;
    for (data[start_index..]) |byte| {
        if (byte != padding_length) {
            return null;
        }
    }

    return data[0..start_index];
}

// Encryption
fn installAesEncryption(aes: *AES) bool {
    var bSTATE: bool = true;
    var hAlgorithm: ?*anyopaque = null;
    var hKeyHandle: ?*anyopaque = null;

    var cbResult: ULONG = 0;
    var dwBlockSize: DWORD = 0;
    var cbKeyObject: DWORD = 0;
    var pbKeyObject: ?[*]u8 = null;
    var pbCipherText: ?[*]u8 = null;
    var cbCipherText: DWORD = 0;

    var status: NTSTATUS = STATUS_SUCCESS;

    blk: {
        status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, null, 0);
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptGetProperty(
            hAlgorithm,
            std.unicode.utf8ToUtf16LeStringLiteral("ObjectLength"),
            @ptrCast(&cbKeyObject),
            @sizeOf(DWORD),
            &cbResult,
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptGetProperty[1] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptGetProperty(
            hAlgorithm,
            std.unicode.utf8ToUtf16LeStringLiteral("BlockLength"),
            @ptrCast(&dwBlockSize),
            @sizeOf(DWORD),
            &cbResult,
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptGetProperty[2] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        if (dwBlockSize != 16) {
            bSTATE = false;
            break :blk;
        }
        pbKeyObject = @ptrCast(kernel32.HeapAlloc(kernel32.GetProcessHeap().?, 0, cbKeyObject));
        if (pbKeyObject == null) {
            bSTATE = false;
            break :blk;
        }
        status = BCryptSetProperty(
            hAlgorithm,
            BCRYPT_CHAINING_MODE,
            @ptrCast(@constCast(BCRYPT_CHAIN_MODE_CBC.ptr)),
            @sizeOf(@TypeOf(BCRYPT_CHAIN_MODE_CBC)),
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptSetProperty Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptGenerateSymmetricKey(
            hAlgorithm,
            &hKeyHandle,
            pbKeyObject.?,
            cbKeyObject,
            aes.pKey.?,
            KEY_SIZE,
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptGenerateSymmetricKey Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptEncrypt(
            hKeyHandle,
            aes.pPlainText.?,
            aes.dwPlainSize,
            null,
            aes.pIv.?,
            IV_SIZE,
            null,
            0,
            &cbCipherText,
            BCRYPT_BLOCK_PADDING,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptEncrypt[1] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        pbCipherText = @ptrCast(kernel32.HeapAlloc(kernel32.GetProcessHeap().?, 0, cbCipherText));
        if (pbCipherText == null) {
            bSTATE = false;
            break :blk;
        }
        status = BCryptEncrypt(
            hKeyHandle,
            aes.pPlainText.?,
            aes.dwPlainSize,
            null,
            aes.pIv.?,
            IV_SIZE,
            pbCipherText,
            cbCipherText,
            &cbResult,
            BCRYPT_BLOCK_PADDING,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptEncrypt[2] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
    }
    if (hKeyHandle != null) _ = BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm != null) _ = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject != null) _ = kernel32.HeapFree(kernel32.GetProcessHeap().?, 0, pbKeyObject.?);
    if (pbCipherText != null and bSTATE) {
        aes.pCipherText = pbCipherText;
        aes.dwCipherSize = cbCipherText;
    }
    return bSTATE;
}

// Decryption
fn installAesDecryption(aes: *AES) bool {
    var bSTATE: bool = true;
    var hAlgorithm: ?*anyopaque = null;
    var hKeyHandle: ?*anyopaque = null;

    var cbResult: ULONG = 0;
    var dwBlockSize: DWORD = 0;
    var cbKeyObject: DWORD = 0;
    var pbKeyObject: ?[*]u8 = null;
    var pbPlainText: ?[*]u8 = null;
    var cbPlainText: DWORD = 0;

    var status: NTSTATUS = STATUS_SUCCESS;

    blk: {
        status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, null, 0);
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptGetProperty(
            hAlgorithm,
            std.unicode.utf8ToUtf16LeStringLiteral("ObjectLength"),
            @ptrCast(&cbKeyObject),
            @sizeOf(DWORD),
            &cbResult,
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptGetProperty[1] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptGetProperty(
            hAlgorithm,
            std.unicode.utf8ToUtf16LeStringLiteral("BlockLength"),
            @ptrCast(&dwBlockSize),
            @sizeOf(DWORD),
            &cbResult,
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptGetProperty[2] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        if (dwBlockSize != 16) {
            bSTATE = false;
            break :blk;
        }
        pbKeyObject = @ptrCast(kernel32.HeapAlloc(kernel32.GetProcessHeap().?, 0, cbKeyObject));
        if (pbKeyObject == null) {
            bSTATE = false;
            break :blk;
        }
        status = BCryptSetProperty(
            hAlgorithm,
            BCRYPT_CHAINING_MODE,
            @ptrCast(@constCast(BCRYPT_CHAIN_MODE_CBC.ptr)),
            @sizeOf(@TypeOf(BCRYPT_CHAIN_MODE_CBC)),
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptSetProperty Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptGenerateSymmetricKey(
            hAlgorithm,
            &hKeyHandle,
            pbKeyObject.?,
            cbKeyObject,
            aes.pKey.?,
            KEY_SIZE,
            0,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptGenerateSymmetricKey Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        status = BCryptDecrypt(
            hKeyHandle,
            aes.pCipherText.?,
            aes.dwCipherSize,
            null,
            aes.pIv.?,
            IV_SIZE,
            null,
            0,
            &cbPlainText,
            BCRYPT_BLOCK_PADDING,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptDecrypt[1] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }
        pbPlainText = @ptrCast(kernel32.HeapAlloc(kernel32.GetProcessHeap().?, 0, cbPlainText));
        if (pbPlainText == null) {
            bSTATE = false;
            break :blk;
        }
        status = BCryptDecrypt(
            hKeyHandle,
            aes.pCipherText.?,
            aes.dwCipherSize,
            null,
            aes.pIv.?,
            IV_SIZE,
            pbPlainText,
            cbPlainText,
            &cbResult,
            BCRYPT_BLOCK_PADDING,
        );
        if (!ntSuccess(status)) {
            std.debug.print("[!] BCryptDecrypt[2] Failed With Error: 0x{X:0>8}\n", .{status});
            bSTATE = false;
            break :blk;
        }

        // Remove PKCS#7 padding after successful decryption
        if (pbPlainText != null and cbResult > 0) {
            const decrypted_data = pbPlainText.?[0..cbResult];
            if (removePkcs7Padding(decrypted_data)) |unpadded| {
                cbResult = @intCast(unpadded.len);
            }
        }
    }
    if (hKeyHandle != null) _ = BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm != null) _ = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject != null) _ = kernel32.HeapFree(kernel32.GetProcessHeap().?, 0, pbKeyObject.?);
    if (pbPlainText != null and bSTATE) {
        aes.pPlainText = pbPlainText;
        aes.dwPlainSize = cbResult; // Use the adjusted size after padding removal
    }
    return bSTATE;
}

// Helper function to check if a many-item pointer is null-like
fn isNullPtr(ptr: anytype) bool {
    return @intFromPtr(ptr) == 0;
}

// Wrapper for encryption
fn simpleEncryption(
    pPlainTextData: [*]u8,
    sPlainTextSize: u32,
    pKey: [*]u8,
    pIv: [*]u8,
    pCipherTextData: *?[*]u8,
    sCipherTextSize: *u32,
) bool {
    if (isNullPtr(pPlainTextData) or sPlainTextSize == 0 or isNullPtr(pKey) or isNullPtr(pIv))
        return false;

    var aes = AES{
        .pKey = pKey,
        .pIv = pIv,
        .pPlainText = pPlainTextData,
        .dwPlainSize = sPlainTextSize,
        .pCipherText = null,
        .dwCipherSize = 0,
    };
    if (!installAesEncryption(&aes))
        return false;
    pCipherTextData.* = aes.pCipherText;
    sCipherTextSize.* = aes.dwCipherSize;
    return true;
}

// Wrapper for decryption
fn simpleDecryption(
    pCipherTextData: [*]u8,
    sCipherTextSize: u32,
    pKey: [*]u8,
    pIv: [*]u8,
    pPlainTextData: *?[*]u8,
    sPlainTextSize: *u32,
) bool {
    if (isNullPtr(pCipherTextData) or sCipherTextSize == 0 or isNullPtr(pKey) or isNullPtr(pIv))
        return false;

    var aes = AES{
        .pKey = pKey,
        .pIv = pIv,
        .pPlainText = null,
        .dwPlainSize = 0,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize,
    };
    if (!installAesDecryption(&aes))
        return false;
    pPlainTextData.* = aes.pPlainText;
    sPlainTextSize.* = aes.dwPlainSize;
    return true;
}

pub fn main() !void {
    // --- DECRYPTION PART EXAMPLE ---
    std.debug.print("--- DECRYPTION PART EXAMPLE ---\n\n", .{});
    var p_key = [_]u8{ 0xEB, 0x40, 0x6D, 0x51, 0x9A, 0x15, 0x71, 0xBF, 0x9F, 0x61, 0xA4, 0x1A, 0x0A, 0x6A, 0x3B, 0x46, 0x9E, 0xD0, 0x73, 0x1E, 0x7C, 0x8B, 0xCB, 0x72, 0xD9, 0x88, 0x01, 0x5F, 0xE3, 0x7B, 0x33, 0x63 };
    var p_iv = [_]u8{ 0xEB, 0x40, 0x6D, 0x51, 0x9A, 0x15, 0x71, 0xBF, 0x9F, 0x61, 0xA4, 0x1A, 0x0A, 0x6A, 0x3B, 0x46 };
    var ciphertext = [_]u8{ 0xBB, 0xF4, 0x2D, 0x43, 0x41, 0x72, 0x46, 0x6C, 0x9F, 0xE7, 0xF8, 0xF3, 0x49, 0xAF, 0x83, 0x69, 0xA5, 0x38, 0xBD, 0x0E, 0x56, 0x84, 0xF6, 0x6D, 0x88, 0x72, 0x26, 0x32, 0x5D, 0xBE, 0x1C, 0x70, 0xB4, 0x42, 0xAE, 0xBC, 0x70, 0x07, 0x87, 0x0C, 0x19, 0x5A, 0x79, 0xB2, 0x4B, 0x88, 0x83, 0xA9, 0x6C, 0x3A, 0xF8, 0x7B, 0x1E, 0x37, 0xD8, 0xAF, 0x36, 0x66, 0x30, 0x27, 0xFA, 0xE4, 0x80, 0x60 };
    var p_plaintext: ?[*]u8 = null;
    var dw_plain_size: u32 = 0;

    if (!simpleDecryption(ciphertext[0..].ptr, ciphertext.len, p_key[0..].ptr, p_iv[0..].ptr, &p_plaintext, &dw_plain_size)) {
        std.debug.print("Decryption failed!\n", .{});
        return;
    }
    printHexData("p_key", p_key[0..]);
    printHexData("p_iv", p_iv[0..]);
    printHexData("ciphertext", ciphertext[0..]);
    printHexData("PlainTextInBytes", p_plaintext.?[0..dw_plain_size]);
    std.debug.print("PlainTextDecoded: {s}\n\n", .{p_plaintext.?[0..dw_plain_size]});
    _ = kernel32.HeapFree(kernel32.GetProcessHeap().?, 0, p_plaintext.?);

    // --- ENCRYPTION PART EXAMPLE ---
    std.debug.print("--- ENCRYPTION PART EXAMPLE ---\n\n", .{});
    var plaintext_data = [_]u8{ 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x67, 0x69, 0x76, 0x65, 0x20, 0x42, 0x6c, 0x61, 0x63, 0x6b, 0x2d, 0x48, 0x61, 0x74, 0x2d, 0x5a, 0x69, 0x67, 0x20, 0x61, 0x20, 0x73, 0x74, 0x61, 0x72, 0x21 };
    var key = [_]u8{0} ** KEY_SIZE;
    var iv = [_]u8{0} ** IV_SIZE;
    generateRandomBytes(key[0..]);
    generateRandomBytes(iv[0..]);
    printHexData("pKey", key[0..]);
    printHexData("pIv", iv[0..]);
    printHexData("PlainTextInBytes", plaintext_data[0..]);
    std.debug.print("PlainTextDecoded: {s}\n\n", .{plaintext_data[0..]});
    var p_ciphertext: ?[*]u8 = null;
    var dw_cipher_size: u32 = 0;
    if (!simpleEncryption(plaintext_data[0..].ptr, plaintext_data.len, key[0..].ptr, iv[0..].ptr, &p_ciphertext, &dw_cipher_size)) {
        std.debug.print("Encryption failed!\n", .{});
        return;
    }
    printHexData("CipherText", p_ciphertext.?[0..dw_cipher_size]);
    _ = kernel32.HeapFree(kernel32.GetProcessHeap().?, 0, p_ciphertext.?);
}
```

## Using Standard Library

```zig title="main.zig"
const std = @import("std");
const crypto = std.crypto;
const Aes256 = crypto.core.aes.Aes256;
const print = std.debug.print;

const KEY_SIZE = 32;
const IV_SIZE = 16;
const BLOCK_SIZE = 16;

// Generate random bytes
fn generateRandomBytes(buf: []u8) !void {
    var prng = std.Random.DefaultPrng.init(@as(u64, @bitCast(std.time.milliTimestamp())));
    const rand = prng.random();
    for (buf) |*b| b.* = rand.int(u8);
}

// Print a buffer as a hex array
fn printHexData(name: []const u8, data: []const u8) void {
    print("const {s} = [_]u8{{", .{name});
    var i: usize = 0;
    for (data) |b| {
        if (i % 16 == 0) print("\n\t", .{});
        if (i < data.len - 1) {
            print("0x{X:0>2}, ", .{b});
        } else {
            print("0x{X:0>2} ", .{b});
        }
        i += 1;
    }
    print("\n}};\n\n", .{});
}

// Add PKCS#7 padding
fn addPkcs7Padding(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const padding_needed = BLOCK_SIZE - (data.len % BLOCK_SIZE);
    const padded_size = data.len + padding_needed;

    var padded_data = try allocator.alloc(u8, padded_size);
    @memcpy(padded_data[0..data.len], data);

    // Fill padding bytes with the padding length value
    @memset(padded_data[data.len..], @intCast(padding_needed));

    return padded_data;
}

// Remove PKCS#7 padding
fn removePkcs7Padding(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) return error.InvalidPadding;

    const padding_length = data[data.len - 1];

    // Validate padding length
    if (padding_length == 0 or padding_length > BLOCK_SIZE or padding_length > data.len) {
        return error.InvalidPadding;
    }

    // Validate all padding bytes are the same
    const start_index = data.len - padding_length;
    for (data[start_index..]) |byte| {
        if (byte != padding_length) {
            return error.InvalidPadding;
        }
    }

    // Return unpadded data
    const unpadded = try allocator.alloc(u8, start_index);
    @memcpy(unpadded, data[0..start_index]);
    return unpadded;
}

// AES-256-CBC Encryption
fn aesEncrypt(allocator: std.mem.Allocator, plaintext: []const u8, key: []const u8, iv: []const u8) ![]u8 {
    if (key.len != KEY_SIZE) return error.InvalidKeySize;
    if (iv.len != IV_SIZE) return error.InvalidIvSize;

    // Add PKCS#7 padding
    const padded_plaintext = try addPkcs7Padding(allocator, plaintext);
    defer allocator.free(padded_plaintext);

    // Initialize AES context
    const aes_ctx = Aes256.initEnc(key[0..32].*);

    // Allocate memory for ciphertext
    var ciphertext = try allocator.alloc(u8, padded_plaintext.len);

    // Copy IV to working buffer
    var working_iv: [IV_SIZE]u8 = undefined;
    @memcpy(&working_iv, iv[0..IV_SIZE]);

    // Encrypt in CBC mode
    var i: usize = 0;
    while (i < padded_plaintext.len) : (i += BLOCK_SIZE) {
        // Prepare block for encryption
        var block: [BLOCK_SIZE]u8 = undefined;

        // XOR with IV/previous ciphertext block
        for (0..BLOCK_SIZE) |j| {
            block[j] = padded_plaintext[i + j] ^ working_iv[j];
        }

        // Encrypt the block
        var encrypted_block: [BLOCK_SIZE]u8 = undefined;
        aes_ctx.encrypt(&encrypted_block, &block);

        // Copy encrypted block to ciphertext
        @memcpy(ciphertext[i .. i + BLOCK_SIZE], &encrypted_block);

        // Update IV with current ciphertext block for next iteration
        @memcpy(&working_iv, &encrypted_block);
    }

    return ciphertext;
}

// AES-256-CBC Decryption
fn aesDecrypt(allocator: std.mem.Allocator, ciphertext: []const u8, key: []const u8, iv: []const u8) ![]u8 {
    if (key.len != KEY_SIZE) return error.InvalidKeySize;
    if (iv.len != IV_SIZE) return error.InvalidIvSize;
    if (ciphertext.len % BLOCK_SIZE != 0) return error.InvalidCiphertextLength;

    // Initialize AES context for decryption
    const aes_ctx = Aes256.initDec(key[0..32].*);

    // Allocate memory for plaintext
    var plaintext = try allocator.alloc(u8, ciphertext.len);

    // Copy IV to working buffer
    var working_iv: [IV_SIZE]u8 = undefined;
    @memcpy(&working_iv, iv[0..IV_SIZE]);

    // Decrypt in CBC mode
    var i: usize = 0;
    while (i < ciphertext.len) : (i += BLOCK_SIZE) {
        // Get current ciphertext block
        var cipher_block: [BLOCK_SIZE]u8 = undefined;
        @memcpy(&cipher_block, ciphertext[i .. i + BLOCK_SIZE]);

        // Decrypt the block
        var decrypted_block: [BLOCK_SIZE]u8 = undefined;
        aes_ctx.decrypt(&decrypted_block, &cipher_block);

        // XOR with IV/previous ciphertext block
        for (0..BLOCK_SIZE) |j| {
            plaintext[i + j] = decrypted_block[j] ^ working_iv[j];
        }

        // Update IV with current ciphertext block for next iteration
        @memcpy(&working_iv, &cipher_block);
    }

    // Remove PKCS#7 padding
    const unpadded = try removePkcs7Padding(allocator, plaintext);
    allocator.free(plaintext); // Free the padded version
    return unpadded;
}

// Simple encryption wrapper
fn simpleEncryption(
    allocator: std.mem.Allocator,
    plaintext_data: []const u8,
    key: []const u8,
    iv: []const u8,
) ![]u8 {
    return aesEncrypt(allocator, plaintext_data, key, iv);
}

// Simple decryption wrapper
fn simpleDecryption(
    allocator: std.mem.Allocator,
    ciphertext_data: []const u8,
    key: []const u8,
    iv: []const u8,
) ![]u8 {
    return aesDecrypt(allocator, ciphertext_data, key, iv);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // --- DECRYPTION PART EXAMPLE ---
    print("--- DECRYPTION PART EXAMPLE ---\n\n", .{});

    const p_key = [_]u8{ 0xEB, 0x40, 0x6D, 0x51, 0x9A, 0x15, 0x71, 0xBF, 0x9F, 0x61, 0xA4, 0x1A, 0x0A, 0x6A, 0x3B, 0x46, 0x9E, 0xD0, 0x73, 0x1E, 0x7C, 0x8B, 0xCB, 0x72, 0xD9, 0x88, 0x01, 0x5F, 0xE3, 0x7B, 0x33, 0x63 };
    const p_iv = [_]u8{ 0xEB, 0x40, 0x6D, 0x51, 0x9A, 0x15, 0x71, 0xBF, 0x9F, 0x61, 0xA4, 0x1A, 0x0A, 0x6A, 0x3B, 0x46 };
    const ciphertext = [_]u8{ 0xBB, 0xF4, 0x2D, 0x43, 0x41, 0x72, 0x46, 0x6C, 0x9F, 0xE7, 0xF8, 0xF3, 0x49, 0xAF, 0x83, 0x69, 0xA5, 0x38, 0xBD, 0x0E, 0x56, 0x84, 0xF6, 0x6D, 0x88, 0x72, 0x26, 0x32, 0x5D, 0xBE, 0x1C, 0x70, 0xB4, 0x42, 0xAE, 0xBC, 0x70, 0x07, 0x87, 0x0C, 0x19, 0x5A, 0x79, 0xB2, 0x4B, 0x88, 0x83, 0xA9, 0x6C, 0x3A, 0xF8, 0x7B, 0x1E, 0x37, 0xD8, 0xAF, 0x36, 0x66, 0x30, 0x27, 0xFA, 0xE4, 0x80, 0x60 };

    const p_plaintext = simpleDecryption(allocator, &ciphertext, &p_key, &p_iv) catch |err| {
        print("Decryption failed: {}\n", .{err});
        return;
    };
    defer allocator.free(p_plaintext);

    printHexData("p_key", &p_key);
    printHexData("p_iv", &p_iv);
    printHexData("ciphertext", &ciphertext);
    printHexData("PlainTextInBytes", p_plaintext);
    print("PlainTextDecoded: {s}\n\n", .{p_plaintext});

    // --- ENCRYPTION PART EXAMPLE ---
    print("--- ENCRYPTION PART EXAMPLE ---\n\n", .{});

    const plaintext_data = [_]u8{ 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x67, 0x69, 0x76, 0x65, 0x20, 0x42, 0x6c, 0x61, 0x63, 0x6b, 0x2d, 0x48, 0x61, 0x74, 0x2d, 0x5a, 0x69, 0x67, 0x20, 0x61, 0x20, 0x73, 0x74, 0x61, 0x72, 0x21 };

    var key: [KEY_SIZE]u8 = undefined;
    var iv: [IV_SIZE]u8 = undefined;
    try generateRandomBytes(&key);
    try generateRandomBytes(&iv);

    printHexData("pKey", &key);
    printHexData("pIv", &iv);
    printHexData("PlainTextInBytes", &plaintext_data);
    print("PlainTextDecoded: {s}\n\n", .{plaintext_data});

    const p_ciphertext = simpleEncryption(allocator, &plaintext_data, &key, &iv) catch |err| {
        print("Encryption failed: {}\n", .{err});
        return;
    };
    defer allocator.free(p_ciphertext);

    printHexData("CipherText", p_ciphertext);

    // --- VERIFICATION: Decrypt what we just encrypted ---
    print("--- VERIFICATION ---\n\n", .{});

    const verification_plaintext = simpleDecryption(allocator, p_ciphertext, &key, &iv) catch |err| {
        print("Verification decryption failed: {}\n", .{err});
        return;
    };
    defer allocator.free(verification_plaintext);

    print("Verification PlainText: {s}\n", .{verification_plaintext});
    print("Original == Decrypted: {}\n", .{std.mem.eql(u8, &plaintext_data, verification_plaintext)});
}
```

## Using Tiny AES

[Originl C project](https://github.com/kokke/tiny-AES-c)

You should go to that project and download the `aes.h` & `aes.c`, then put them into your `src` directory. Then you should add this to your `build.zig` to make the Zig compiler know where's your C source.

```zig title="build.zig"
// NOTE: This allow the compiler to link the C source
exe.addCSourceFile(.{ .file = b.path("src/aes.c"), .flags = &.{} });
exe.addIncludePath(b.path("src"));
exe.linkLibC();
```

```zig title="main.zig"
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
```
