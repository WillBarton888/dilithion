// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Base58 encoding/decoding
 *
 * Tests Base58 codec with random inputs, focusing on:
 * - Encoding arbitrary binary data
 * - Decoding malformed strings
 * - Round-trip encoding/decoding
 * - Edge cases (empty, very long, invalid characters)
 *
 * Priority: HIGH (used in address handling)
 */

#include "fuzz.h"
#include "util.h"
#include "../../util/base58.h"
#include <vector>
#include <string>
#include <cassert>

FUZZ_TARGET(base58_codec)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Test 1: Encode random binary data
        {
            size_t data_len = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100);
            std::vector<uint8_t> binary = fuzzed_data.ConsumeBytes<uint8_t>(data_len);

            std::string encoded = EncodeBase58(binary);

            // Verify decoding works
            std::vector<uint8_t> decoded;
            bool success = DecodeBase58(encoded, decoded);

            assert(success);
            assert(decoded == binary);
        }

        // Test 2: Decode random strings
        {
            std::string random_str = fuzzed_data.ConsumeRandomLengthString(100);

            std::vector<uint8_t> decoded;
            bool success = DecodeBase58(random_str, decoded);

            if (success) {
                // Valid Base58 string - try to encode it back
                std::string re_encoded = EncodeBase58(decoded);

                // Should be able to decode again
                std::vector<uint8_t> decoded2;
                bool success2 = DecodeBase58(re_encoded, decoded2);

                assert(success2);
                assert(decoded == decoded2);
            }
        }

        // Test 3: Edge cases
        {
            // Empty string
            std::vector<uint8_t> decoded_empty;
            DecodeBase58("", decoded_empty);

            // Invalid characters (0, O, I, l are not in Base58)
            std::vector<uint8_t> decoded_invalid;
            DecodeBase58("0OIl", decoded_invalid);  // Should fail

            // Very long string
            std::string long_str(1000, '1');
            std::vector<uint8_t> decoded_long;
            DecodeBase58(long_str, decoded_long);
        }

    } catch (const std::exception& e) {
        return;
    }
}
