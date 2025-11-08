// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Address encoding (Base58)
 *
 * Tests encoding public key hash to Base58 address with checksum.
 * Extracted from fuzz_address.cpp multi-target file.
 */

#include "fuzz.h"
#include "util.h"
#include "../../crypto/sha3.h"
#include "../../util/base58.h"
#include <cassert>
#include <vector>
#include <string>

FUZZ_TARGET(address_base58_encode)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Fuzz version byte
        uint8_t version = fuzzed_data.ConsumeIntegral<uint8_t>();

        // Fuzz public key hash (typically 20 bytes)
        size_t hash_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 32);
        std::vector<uint8_t> pubkey_hash = fuzzed_data.ConsumeBytes<uint8_t>(hash_size);

        // Build address data
        std::vector<uint8_t> address_data;
        address_data.push_back(version);
        address_data.insert(address_data.end(), pubkey_hash.begin(), pubkey_hash.end());

        // Calculate checksum
        uint8_t hash1[32];
        SHA3_256(address_data.data(), address_data.size(), hash1);

        uint8_t hash2[32];
        SHA3_256(hash1, 32, hash2);

        // Append first 4 bytes as checksum
        address_data.insert(address_data.end(), hash2, hash2 + 4);

        // Encode to Base58
        std::string address_str = EncodeBase58(address_data);

        // Verify we can decode it back
        std::vector<uint8_t> decoded;
        bool success = DecodeBase58(address_str, decoded);

        assert(success);
        assert(decoded == address_data);

    } catch (const std::exception& e) {
        return;
    }
}
