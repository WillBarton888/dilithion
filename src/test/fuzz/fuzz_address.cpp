// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * NOTE: This file contains multiple fuzz targets wrapped in #if 0 blocks.
 * libFuzzer allows only ONE FUZZ_TARGET per binary.
 */

#include "fuzz.h"
#include "util.h"
#include "../../crypto/sha3.h"
#include "../../util/base58.h"
#include <cassert>
#include <vector>
#include <string>

/**
 * Fuzz target: Address parsing and validation
 *
 * Tests:
 * - Base58 decoding
 * - Address checksum validation
 * - Version byte handling
 * - Bech32 decoding (if supported)
 * - Invalid address rejection
 * - Address type detection
 *
 * Coverage:
 * - src/base58.cpp
 * - src/address.cpp (if exists)
 *
 * Based on gap analysis: Wallet address handling
 * Priority: MEDIUM (user-facing, security)
 */

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

#if 0
/**
 * Fuzz target: Address encoding
 *
 * Tests encoding public key hash to address
 */
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
#endif

#if 0
/**
 * Fuzz target: Address validation
 *
 * Tests address validation logic
 */
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
#endif

#if 0
/**
 * Fuzz target: Bech32 address decoding (if supported)
 *
 * Tests Bech32 encoding used by SegWit addresses
 */
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
#endif

#if 0
/**
 * Fuzz target: Address type detection
 *
 * Tests detecting address type from string
 */
FUZZ_TARGET(address_type_detect)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        std::string address = fuzzed_data.ConsumeRandomLengthString(100);

        // Detect address type

        if (address.length() >= 26 && address.length() <= 35) {
            // Possible Base58 address
            if (address[0] == '1') {
                // Likely P2PKH mainnet
            } else if (address[0] == '3') {
                // Likely P2SH mainnet
            } else if (address[0] == 'm' || address[0] == 'n') {
                // Likely testnet P2PKH
            } else if (address[0] == '2') {
                // Likely testnet P2SH
            }
        } else if (address.find("bc1") == 0 || address.find("tb1") == 0) {
            // Bech32 address
            if (address.find("bc1") == 0) {
                // Mainnet SegWit
            } else {
                // Testnet SegWit
            }
        } else {
            // Unknown format
        }

    } catch (const std::exception& e) {
        return;
    }
}
#endif
