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
