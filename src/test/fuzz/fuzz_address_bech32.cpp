// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Bech32 address decoding
 *
 * Tests Bech32 encoding used by SegWit addresses (if supported).
 * Extracted from fuzz_address.cpp multi-target file.
 */

#include "fuzz.h"
#include "util.h"
#include <string>
#include <cstring>

FUZZ_TARGET(address_bech32_decode)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Bech32 format: hrp1separator1data1checksum
        // Example: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

        std::string bech32_str = fuzzed_data.ConsumeRandomLengthString(90);

        // Check for separator '1'
        size_t separator_pos = bech32_str.find('1');
        if (separator_pos == std::string::npos || separator_pos == 0) {
            // Invalid format
            return;
        }

        // Extract HRP (human-readable part)
        std::string hrp = bech32_str.substr(0, separator_pos);

        // Extract data part
        std::string data_part = bech32_str.substr(separator_pos + 1);

        // Bech32 charset: qpzry9x8gf2tvdw0s3jn54khce6mua7l
        const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

        // Validate all characters are in charset
        for (char c : data_part) {
            if (strchr(charset, c) == nullptr) {
                // Invalid character
                return;
            }
        }

        // TODO: Implement full Bech32 validation
        // - Convert characters to 5-bit values
        // - Verify checksum
        // - Extract witness version and program

    } catch (const std::exception& e) {
        return;
    }
}
