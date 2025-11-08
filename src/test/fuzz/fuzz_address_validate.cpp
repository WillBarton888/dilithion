// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Address validation
 *
 * Tests address validation logic including checksum verification.
 * Extracted from fuzz_address.cpp multi-target file.
 */

#include "fuzz.h"
#include "util.h"
#include "../../crypto/sha3.h"
#include "../../util/base58.h"
#include <cassert>
#include <vector>
#include <string>

FUZZ_TARGET(address_validate)
{
    FuzzedDataProvider fuzzed_data(data, size);

    // Test various invalid addresses
    std::vector<std::string> test_addresses = {
        "",                                    // Empty
        "1",                                   // Too short
        "0000000000000000000000000000000000", // Invalid Base58
        "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII", // Invalid characters
        fuzzed_data.ConsumeRandomLengthString(50), // Random string
    };

    for (const auto& addr : test_addresses) {
        try {
            std::vector<uint8_t> decoded;
            bool valid = DecodeBase58(addr, decoded);

            if (valid && decoded.size() >= 25) {
                // Check checksum
                std::vector<uint8_t> data_to_hash(decoded.begin(), decoded.end() - 4);
                uint32_t checksum_provided = *reinterpret_cast<const uint32_t*>(&decoded[decoded.size() - 4]);

                uint8_t hash1[32];
                SHA3_256(data_to_hash.data(), data_to_hash.size(), hash1);

                uint8_t hash2[32];
                SHA3_256(hash1, 32, hash2);

                uint32_t checksum_calculated = *reinterpret_cast<const uint32_t*>(hash2);

                if (checksum_provided == checksum_calculated) {
                    // Valid address
                } else {
                    // Invalid checksum
                }
            }

        } catch (const std::exception& e) {
            // Expected for invalid addresses
        }
    }
}
