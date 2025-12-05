// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/strencodings.h>
#include <algorithm>
#include <cctype>

/**
 * Task 2.1: Hex String Encoding/Decoding Utilities
 *
 * These functions enable transaction hex serialization for RPC methods.
 */

std::string HexStr(const uint8_t* data, size_t len) {
    static const char hexmap[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string result;
    result.reserve(len * 2);

    for (size_t i = 0; i < len; ++i) {
        result.push_back(hexmap[(data[i] >> 4) & 0x0F]);  // High nibble
        result.push_back(hexmap[data[i] & 0x0F]);         // Low nibble
    }

    // CID 1675315 FIX: Use std::move to avoid unnecessary copy
    return std::move(result);
}

std::string HexStr(const std::vector<uint8_t>& vch) {
    return HexStr(vch.data(), vch.size());
}

std::vector<uint8_t> ParseHex(const std::string& str) {
    // Check for valid hex string
    if (!IsHex(str)) {
        return std::vector<uint8_t>();  // Return empty vector on invalid input
    }

    std::vector<uint8_t> result;
    result.reserve(str.size() / 2);

    for (size_t i = 0; i < str.size(); i += 2) {
        int8_t high = HexDigit(str[i]);
        int8_t low = HexDigit(str[i + 1]);

        if (high < 0 || low < 0) {
            return std::vector<uint8_t>();  // Invalid hex digit
        }

        result.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    // CID 1675315 FIX: Use std::move to avoid unnecessary copy
    return std::move(result);
}

bool IsHex(const std::string& str) {
    // Must have even number of characters
    if (str.size() % 2 != 0) {
        return false;
    }

    // Must contain only hex digits
    for (char c : str) {
        if (HexDigit(c) < 0) {
            return false;
        }
    }

    return true;
}
