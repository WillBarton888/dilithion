// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_TEST_FUZZ_HELPERS_H
#define DILITHION_TEST_FUZZ_HELPERS_H

#include <primitives/block.h>
#include <string>
#include <cstring>

/**
 * Helper functions for fuzz testing
 */

/**
 * Create uint256 from hex string
 * Simplified version for fuzz testing
 */
inline uint256 uint256FromHex(const std::string& hex_str) {
    uint256 result;

    // Convert hex string to bytes
    std::string hex = hex_str;
    if (hex.length() > 64) {
        hex = hex.substr(0, 64);
    }

    // Pad if too short
    while (hex.length() < 64) {
        hex = "0" + hex;
    }

    // Convert to bytes (simplified, assumes valid hex)
    for (size_t i = 0; i < 32 && i * 2 < hex.length(); ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        result.data[31 - i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }

    return result;
}

/**
 * Create uint256 from fuzzed data
 */
inline uint256 uint256FromFuzz(const uint8_t* data, size_t size) {
    uint256 result;
    size_t copy_size = std::min(size, sizeof(result.data));
    if (copy_size > 0) {
        std::memcpy(result.data, data, copy_size);
    }
    return result;
}

#endif // DILITHION_TEST_FUZZ_HELPERS_H
