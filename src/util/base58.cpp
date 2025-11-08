// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include "base58.h"
#include "../crypto/sha3.h"
#include <cstring>

// Base58 alphabet (Bitcoin-style, no confusing characters: 0, O, I, l)
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// VULN-006 FIX: Prevent DoS via excessively long Base58 strings
static const size_t MAX_BASE58_LEN = 1024;  // Reasonable limit for addresses

std::string EncodeBase58(const std::vector<uint8_t>& data) {
    // Skip leading zeroes
    size_t zeroes = 0;
    while (zeroes < data.size() && data[zeroes] == 0) {
        zeroes++;
    }

    // Allocate enough space in base58
    std::vector<uint8_t> b58((data.size() - zeroes) * 138 / 100 + 1);
    size_t length = 0;

    // Process the bytes
    for (size_t i = zeroes; i < data.size(); ++i) {
        int carry = data[i];
        for (size_t j = 0; j < length; ++j) {
            carry += 256 * b58[j];
            b58[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            b58[length++] = carry % 58;
            carry /= 58;
        }
    }

    // Convert to string
    std::string str;
    str.reserve(zeroes + length);

    // Add leading '1's for leading zero bytes
    for (size_t i = 0; i < zeroes; ++i) {
        str += pszBase58[0];
    }

    // Add base58-encoded data (reversed)
    for (size_t i = 0; i < length; ++i) {
        str += pszBase58[b58[length - 1 - i]];
    }

    return str;
}

bool DecodeBase58(const std::string& str, std::vector<uint8_t>& data) {
    // VULN-006 FIX: Prevent DoS via excessively long Base58 strings
    if (str.size() > MAX_BASE58_LEN) {
        return false;  // Reject maliciously long input
    }

    // Simple implementation - convert from base58
    std::vector<uint8_t> vch;
    vch.reserve(str.size() * 138 / 100 + 1);

    // Skip leading '1's
    size_t zeroes = 0;
    while (zeroes < str.size() && str[zeroes] == pszBase58[0]) {
        zeroes++;
    }

    // Decode base58
    for (size_t i = zeroes; i < str.size(); ++i) {
        const char* p = strchr(pszBase58, str[i]);
        if (p == nullptr) {
            return false;  // Invalid character
        }
        int carry = p - pszBase58;
        for (size_t j = 0; j < vch.size(); ++j) {
            carry += 58 * vch[j];
            vch[j] = carry % 256;
            carry /= 256;
        }
        while (carry > 0) {
            vch.push_back(carry % 256);
            carry /= 256;
        }
    }

    // Add leading zeros
    data.assign(zeroes, 0);
    data.insert(data.end(), vch.rbegin(), vch.rend());

    return true;
}

std::string EncodeBase58Check(const std::vector<uint8_t>& data) {
    // Add checksum (double SHA3-256 of data, first 4 bytes)
    std::vector<uint8_t> vchChecksum(32);
    SHA3_256(data.data(), data.size(), vchChecksum.data());
    SHA3_256(vchChecksum.data(), 32, vchChecksum.data());

    // Combine data + checksum
    std::vector<uint8_t> vch = data;
    vch.insert(vch.end(), vchChecksum.begin(), vchChecksum.begin() + 4);

    // Convert to base58
    return EncodeBase58(vch);
}

bool DecodeBase58Check(const std::string& str, std::vector<uint8_t>& data) {
    // VULN-006 FIX: Prevent DoS via excessively long Base58 strings
    if (str.size() > MAX_BASE58_LEN) {
        return false;  // Reject maliciously long input
    }

    // Decode base58
    std::vector<uint8_t> vch;
    if (!DecodeBase58(str, vch)) {
        return false;
    }

    if (vch.size() < 4) {
        return false;  // Too short for checksum
    }

    // Verify checksum
    std::vector<uint8_t> payload(vch.begin(), vch.end() - 4);
    std::vector<uint8_t> checksum(vch.end() - 4, vch.end());

    uint8_t hash[32];
    SHA3_256(payload.data(), payload.size(), hash);
    SHA3_256(hash, 32, hash);

    if (memcmp(checksum.data(), hash, 4) != 0) {
        return false;  // Checksum mismatch
    }

    data = payload;
    return true;
}
