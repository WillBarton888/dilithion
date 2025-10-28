// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/crypter.h>
#include <crypto/sha3.h>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/**
 * PKCS#7 Padding
 *
 * Adds padding to make data a multiple of block size (16 bytes for AES).
 * Padding value = number of padding bytes added.
 *
 * Example: If 3 bytes needed, append [0x03, 0x03, 0x03]
 */
static void AddPKCS7Padding(std::vector<uint8_t>& data, size_t blockSize) {
    size_t paddingLen = blockSize - (data.size() % blockSize);
    data.insert(data.end(), paddingLen, static_cast<uint8_t>(paddingLen));
}

/**
 * Remove PKCS#7 Padding
 *
 * Validates and removes padding from decrypted data.
 *
 * @param data Data with padding
 * @return true if padding is valid and removed, false if invalid padding
 */
static bool RemovePKCS7Padding(std::vector<uint8_t>& data, size_t blockSize) {
    if (data.empty()) return false;

    uint8_t paddingLen = data.back();

    // Validate padding length
    if (paddingLen == 0 || paddingLen > blockSize || paddingLen > data.size()) {
        return false;
    }

    // Validate all padding bytes are correct
    for (size_t i = data.size() - paddingLen; i < data.size(); i++) {
        if (data[i] != paddingLen) {
            return false;
        }
    }

    // Remove padding
    data.resize(data.size() - paddingLen);
    return true;
}

/**
 * XOR two byte arrays
 *
 * Used in CBC mode: ciphertext[i] = Encrypt(plaintext[i] XOR ciphertext[i-1])
 */
static void XORBytes(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/**
 * Simple AES-256 Implementation
 *
 * Note: This is a minimal, educational implementation.
 * For production, consider using OpenSSL or a hardware-accelerated library.
 *
 * This implementation uses a simplified AES based on lookup tables.
 * It's sufficient for wallet encryption but not optimized for high throughput.
 */

// AES S-box (substitution box)
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Inverse S-box (for decryption)
static const uint8_t AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon (round constant) for key expansion
static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/**
 * Galois Field GF(2^8) Multiplication
 *
 * Multiplies two bytes in GF(2^8) with modulo by irreducible polynomial 0x11B.
 * This is required for AES MixColumns operation.
 */
static uint8_t GF_Mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        bool highBitSet = (a & 0x80) != 0;
        a <<= 1;
        if (highBitSet) {
            a ^= 0x1B;  // Modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return result;
}

/**
 * AES-256 Key Expansion
 *
 * Expands 32-byte key into 15 round keys (240 bytes total).
 * AES-256 uses 14 rounds.
 */
static void AES256_KeyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    memcpy(roundKeys, key, 32);

    for (int i = 8; i < 60; i++) {
        uint8_t temp[4];
        memcpy(temp, roundKeys + (i - 1) * 4, 4);

        if (i % 8 == 0) {
            // RotWord
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            // SubWord
            temp[0] = AES_SBOX[temp[0]];
            temp[1] = AES_SBOX[temp[1]];
            temp[2] = AES_SBOX[temp[2]];
            temp[3] = AES_SBOX[temp[3]];

            temp[0] ^= RCON[i / 8];
        } else if (i % 8 == 4) {
            // SubWord only
            temp[0] = AES_SBOX[temp[0]];
            temp[1] = AES_SBOX[temp[1]];
            temp[2] = AES_SBOX[temp[2]];
            temp[3] = AES_SBOX[temp[3]];
        }

        for (int j = 0; j < 4; j++) {
            roundKeys[i * 4 + j] = roundKeys[(i - 8) * 4 + j] ^ temp[j];
        }
    }
}

/**
 * AES Block Encryption (single 16-byte block)
 */
static void AES256_EncryptBlock(const uint8_t* plaintext, const uint8_t* roundKeys, uint8_t* ciphertext) {
    uint8_t state[16];
    memcpy(state, plaintext, 16);

    // Initial round key addition
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKeys[i];
    }

    // Rounds 1-13
    for (int round = 1; round < 14; round++) {
        // SubBytes
        for (int i = 0; i < 16; i++) {
            state[i] = AES_SBOX[state[i]];
        }

        // ShiftRows
        uint8_t temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;

        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;

        temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;

        // MixColumns (using proper GF(2^8) multiplication)
        uint8_t tmp[16];
        memcpy(tmp, state, 16);
        for (int i = 0; i < 4; i++) {
            state[i*4]   = GF_Mul(0x02, tmp[i*4]) ^ GF_Mul(0x03, tmp[i*4+1]) ^ tmp[i*4+2] ^ tmp[i*4+3];
            state[i*4+1] = tmp[i*4] ^ GF_Mul(0x02, tmp[i*4+1]) ^ GF_Mul(0x03, tmp[i*4+2]) ^ tmp[i*4+3];
            state[i*4+2] = tmp[i*4] ^ tmp[i*4+1] ^ GF_Mul(0x02, tmp[i*4+2]) ^ GF_Mul(0x03, tmp[i*4+3]);
            state[i*4+3] = GF_Mul(0x03, tmp[i*4]) ^ tmp[i*4+1] ^ tmp[i*4+2] ^ GF_Mul(0x02, tmp[i*4+3]);
        }

        // AddRoundKey
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKeys[round * 16 + i];
        }
    }

    // Final round (no MixColumns)
    for (int i = 0; i < 16; i++) {
        state[i] = AES_SBOX[state[i]];
    }

    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;

    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKeys[224 + i];  // Round 14 key
    }

    memcpy(ciphertext, state, 16);
}

/**
 * AES Block Decryption (single 16-byte block)
 */
static void AES256_DecryptBlock(const uint8_t* ciphertext, const uint8_t* roundKeys, uint8_t* plaintext) {
    uint8_t state[16];
    memcpy(state, ciphertext, 16);

    // Initial round key addition (reverse order)
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKeys[224 + i];
    }

    // Rounds 13-1 (reverse)
    for (int round = 13; round >= 1; round--) {
        // Inverse ShiftRows
        uint8_t temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;

        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;

        temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;

        // Inverse SubBytes
        for (int i = 0; i < 16; i++) {
            state[i] = AES_INV_SBOX[state[i]];
        }

        // AddRoundKey
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKeys[round * 16 + i];
        }

        // Inverse MixColumns (using proper GF(2^8) multiplication)
        uint8_t tmp[16];
        memcpy(tmp, state, 16);
        for (int i = 0; i < 4; i++) {
            state[i*4]   = GF_Mul(0x0e, tmp[i*4]) ^ GF_Mul(0x0b, tmp[i*4+1]) ^ GF_Mul(0x0d, tmp[i*4+2]) ^ GF_Mul(0x09, tmp[i*4+3]);
            state[i*4+1] = GF_Mul(0x09, tmp[i*4]) ^ GF_Mul(0x0e, tmp[i*4+1]) ^ GF_Mul(0x0b, tmp[i*4+2]) ^ GF_Mul(0x0d, tmp[i*4+3]);
            state[i*4+2] = GF_Mul(0x0d, tmp[i*4]) ^ GF_Mul(0x09, tmp[i*4+1]) ^ GF_Mul(0x0e, tmp[i*4+2]) ^ GF_Mul(0x0b, tmp[i*4+3]);
            state[i*4+3] = GF_Mul(0x0b, tmp[i*4]) ^ GF_Mul(0x0d, tmp[i*4+1]) ^ GF_Mul(0x09, tmp[i*4+2]) ^ GF_Mul(0x0e, tmp[i*4+3]);
        }
    }

    // Inverse final round
    uint8_t temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;

    for (int i = 0; i < 16; i++) {
        state[i] = AES_INV_SBOX[state[i]];
    }

    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKeys[i];
    }

    memcpy(plaintext, state, 16);
}

// ============================================================================
// CCrypter Implementation
// ============================================================================

bool CCrypter::SetKey(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    if (key.size() != 32) return false;  // AES-256 requires 32-byte key
    if (iv.size() != 16) return false;   // AES requires 16-byte IV

    memcpy(vchKey.data_ptr(), key.data(), 32);
    memcpy(vchIV.data(), iv.data(), 16);
    fKeySet = true;

    return true;
}

bool CCrypter::EncryptAES256(const std::vector<uint8_t>& plaintext,
                             std::vector<uint8_t>& ciphertext) {
    if (!fKeySet) return false;
    if (plaintext.empty()) return false;

    // Expand key
    uint8_t roundKeys[240];
    AES256_KeyExpansion(vchKey.data_ptr(), roundKeys);

    // Add PKCS#7 padding
    std::vector<uint8_t> padded = plaintext;
    AddPKCS7Padding(padded, 16);

    // Encrypt using CBC mode
    ciphertext.resize(padded.size());
    std::vector<uint8_t> prevCipherBlock(vchIV.begin(), vchIV.end());

    for (size_t i = 0; i < padded.size(); i += 16) {
        uint8_t block[16];
        XORBytes(&padded[i], prevCipherBlock.data(), block, 16);

        AES256_EncryptBlock(block, roundKeys, &ciphertext[i]);

        memcpy(prevCipherBlock.data(), &ciphertext[i], 16);
    }

    // Wipe sensitive data
    memory_cleanse(roundKeys, sizeof(roundKeys));

    return true;
}

bool CCrypter::DecryptAES256(const std::vector<uint8_t>& ciphertext,
                             std::vector<uint8_t>& plaintext) {
    if (!fKeySet) return false;
    if (ciphertext.empty()) return false;
    if (ciphertext.size() % 16 != 0) return false;  // Must be multiple of block size

    // Expand key
    uint8_t roundKeys[240];
    AES256_KeyExpansion(vchKey.data_ptr(), roundKeys);

    // Decrypt using CBC mode
    std::vector<uint8_t> decrypted(ciphertext.size());
    std::vector<uint8_t> prevCipherBlock(vchIV.begin(), vchIV.end());

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        uint8_t block[16];
        AES256_DecryptBlock(&ciphertext[i], roundKeys, block);

        XORBytes(block, prevCipherBlock.data(), &decrypted[i], 16);

        memcpy(prevCipherBlock.data(), &ciphertext[i], 16);
    }

    // Remove padding
    if (!RemovePKCS7Padding(decrypted, 16)) {
        memory_cleanse(roundKeys, sizeof(roundKeys));
        return false;  // Invalid padding (wrong key or corrupted data)
    }

    plaintext = std::move(decrypted);

    // Wipe sensitive data
    memory_cleanse(roundKeys, sizeof(roundKeys));

    return true;
}

bool CCrypter::Encrypt(const std::vector<uint8_t>& plaintext,
                       std::vector<uint8_t>& ciphertext) {
    return EncryptAES256(plaintext, ciphertext);
}

bool CCrypter::Decrypt(const std::vector<uint8_t>& ciphertext,
                       std::vector<uint8_t>& plaintext) {
    return DecryptAES256(ciphertext, plaintext);
}

// ============================================================================
// Key Derivation (PBKDF2-SHA3)
// ============================================================================

/**
 * PBKDF2-SHA3 Implementation
 *
 * PBKDF2 (Password-Based Key Derivation Function 2) using SHA-3-256 as PRF.
 * This is quantum-resistant due to use of SHA-3 instead of SHA-2.
 *
 * Algorithm:
 *   DK = PBKDF2(PRF, Password, Salt, c, dkLen)
 *   where PRF = HMAC-SHA3-256
 */

// HMAC-SHA3-256
static void HMAC_SHA3_256(const uint8_t* key, size_t keyLen,
                          const uint8_t* data, size_t dataLen,
                          uint8_t* out) {
    const size_t blockSize = 136;  // SHA3-256 rate in bytes
    uint8_t keyPad[blockSize];
    memory_cleanse(keyPad, blockSize);

    if (keyLen <= blockSize) {
        memcpy(keyPad, key, keyLen);
    } else {
        SHA3_256(key, keyLen, keyPad);  // Hash long keys
    }

    // Inner hash: H((key XOR ipad) || data)
    uint8_t ipad[blockSize];
    for (size_t i = 0; i < blockSize; i++) {
        ipad[i] = keyPad[i] ^ 0x36;
    }

    std::vector<uint8_t> inner;
    inner.insert(inner.end(), ipad, ipad + blockSize);
    inner.insert(inner.end(), data, data + dataLen);

    uint8_t innerHash[32];
    SHA3_256(inner.data(), inner.size(), innerHash);

    // Outer hash: H((key XOR opad) || innerHash)
    uint8_t opad[blockSize];
    for (size_t i = 0; i < blockSize; i++) {
        opad[i] = keyPad[i] ^ 0x5c;
    }

    std::vector<uint8_t> outer;
    outer.insert(outer.end(), opad, opad + blockSize);
    outer.insert(outer.end(), innerHash, innerHash + 32);

    SHA3_256(outer.data(), outer.size(), out);

    // Wipe sensitive data
    memory_cleanse(keyPad, blockSize);
    memory_cleanse(ipad, blockSize);
    memory_cleanse(opad, blockSize);
    memory_cleanse(innerHash, 32);
}

bool DeriveKey(const std::string& passphrase,
               const std::vector<uint8_t>& salt,
               unsigned int rounds,
               std::vector<uint8_t>& keyOut) {
    if (passphrase.empty()) return false;
    if (salt.size() != WALLET_CRYPTO_SALT_SIZE) return false;
    if (rounds == 0) return false;

    keyOut.resize(WALLET_CRYPTO_KEY_SIZE);

    // PBKDF2: Generate first block (only need 32 bytes = 1 block for AES-256)
    std::vector<uint8_t> saltBlock(salt.begin(), salt.end());
    saltBlock.push_back(0);
    saltBlock.push_back(0);
    saltBlock.push_back(0);
    saltBlock.push_back(1);  // Block number = 1

    uint8_t U[32];  // U1 = PRF(password, salt || block_number)
    HMAC_SHA3_256(reinterpret_cast<const uint8_t*>(passphrase.data()),
                  passphrase.length(),
                  saltBlock.data(),
                  saltBlock.size(),
                  U);

    memcpy(keyOut.data(), U, 32);  // T = U1

    // Iterate: T = U1 XOR U2 XOR ... XOR Uc
    for (unsigned int i = 1; i < rounds; i++) {
        uint8_t Unext[32];
        HMAC_SHA3_256(reinterpret_cast<const uint8_t*>(passphrase.data()),
                      passphrase.length(),
                      U,
                      32,
                      Unext);

        for (int j = 0; j < 32; j++) {
            keyOut[j] ^= Unext[j];
        }

        memcpy(U, Unext, 32);
    }

    // Wipe sensitive data
    memory_cleanse(U, 32);

    return true;
}

// ============================================================================
// Random Number Generation
// ============================================================================

bool GetStrongRandBytes(uint8_t* buf, size_t len) {
    if (buf == nullptr || len == 0) return false;

#ifdef _WIN32
    // Windows: Use CryptGenRandom
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContextW(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return false;
    }

    bool success = CryptGenRandom(hProvider, static_cast<DWORD>(len), buf);
    CryptReleaseContext(hProvider, 0);
    return success;

#else
    // Unix: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return false;
        }
        total += n;
    }

    close(fd);
    return true;
#endif
}

bool GenerateSalt(std::vector<uint8_t>& salt) {
    salt.resize(WALLET_CRYPTO_SALT_SIZE);
    return GetStrongRandBytes(salt.data(), WALLET_CRYPTO_SALT_SIZE);
}

bool GenerateIV(std::vector<uint8_t>& iv) {
    iv.resize(WALLET_CRYPTO_IV_SIZE);
    return GetStrongRandBytes(iv.data(), WALLET_CRYPTO_IV_SIZE);
}
