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
