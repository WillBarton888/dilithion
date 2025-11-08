// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Address parsing and validation (Base58 decoding)
 *
 * Tests:
 * - Base58 decoding
 * - Address checksum validation
 * - Version byte handling
 * - Invalid address rejection
 *
 * Note: This file previously contained multiple disabled targets.
 * They have been split into separate fuzzer binaries as part of
 * Phase 3 fuzzing infrastructure enhancement (November 2025).
 *
 * Related fuzzers:
 * - fuzz_address_encode.cpp: Base58 encoding
 * - fuzz_address_validate.cpp: Address validation
 * - fuzz_address_bech32.cpp: Bech32 decoding
 * - fuzz_address_type.cpp: Address type detection
 * - fuzz_base58.cpp: Base58 codec
 *
 * Coverage:
 * - src/util/base58.cpp
 *
 * Priority: MEDIUM (user-facing, security)
 */

#include "fuzz.h"
#include "util.h"
#include "../../crypto/sha3.h"
#include "../../util/base58.h"
#include <cassert>
#include <vector>
#include <string>

FUZZ_TARGET(address_base58_decode)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Get fuzzed address string
        std::string address_str = fuzzed_data.ConsumeRandomLengthString(100);

        // Attempt to decode Base58
        std::vector<uint8_t> decoded;
        bool success = DecodeBase58(address_str, decoded);

        if (!success) {
            // Invalid Base58 encoding
            return;
        }

        // Check decoded data has minimum length (version + hash + checksum)
        if (decoded.size() < 25) {
            // Too short to be valid address
            return;
        }

        // Extract components
        uint8_t version = decoded[0];
        std::vector<uint8_t> payload(decoded.begin() + 1, decoded.end() - 4);
        uint32_t checksum_provided = *reinterpret_cast<const uint32_t*>(&decoded[decoded.size() - 4]);

        // Calculate checksum
        std::vector<uint8_t> data_to_hash(decoded.begin(), decoded.end() - 4);

        // Dilithion may use SHA3-256 for address checksums
        uint8_t hash1[32];
        SHA3_256(data_to_hash.data(), data_to_hash.size(), hash1);

        uint8_t hash2[32];
        SHA3_256(hash1, 32, hash2);

        uint32_t checksum_calculated = *reinterpret_cast<const uint32_t*>(hash2);

        // Verify checksum
        if (checksum_provided != checksum_calculated) {
            // Invalid checksum
            return;
        }

        // Valid address
        // Check version byte
        if (version == 0x00) {
            // P2PKH address
        } else if (version == 0x05) {
            // P2SH address
        } else {
            // Unknown version (may be testnet or future version)
        }

    } catch (const std::exception& e) {
        return;
    }
}
