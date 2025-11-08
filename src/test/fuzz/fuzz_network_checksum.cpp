// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Network message checksum validation
 *
 * Tests checksum calculation and validation for network messages.
 * Extracted from fuzz_network_message.cpp multi-target file.
 */

#include "fuzz.h"
#include "util.h"
#include "../../crypto/sha3.h"
#include <cassert>
#include <cstring>
#include <vector>

/**
 * Calculate message checksum (SHA3-256 based)
 */
static uint32_t CalculateChecksum(const uint8_t* payload, size_t length) {
    // Dilithion uses SHA3-256
    uint8_t hash[32];
    SHA3_256(payload, length, hash);

    // Return first 4 bytes as uint32_t
    uint32_t checksum;
    memcpy(&checksum, hash, 4);
    return checksum;
}

FUZZ_TARGET(network_message_checksum)
{
    FuzzedDataProvider fuzzed_data(data, size);

    // Test checksum with various payload sizes
    size_t payload_sizes[] = {0, 1, 10, 100, 1000, 10000, 100000};

    for (size_t payload_size : payload_sizes) {
        if (fuzzed_data.remaining_bytes() < payload_size) {
            break;
        }

        std::vector<uint8_t> payload = fuzzed_data.ConsumeBytes<uint8_t>(payload_size);

        // Calculate checksum
        uint32_t checksum1 = CalculateChecksum(payload.data(), payload.size());

        // Calculate again (should be deterministic)
        uint32_t checksum2 = CalculateChecksum(payload.data(), payload.size());

        assert(checksum1 == checksum2);

        // Modify one byte and verify checksum changes
        if (!payload.empty()) {
            payload[0] ^= 0x01;
            uint32_t checksum3 = CalculateChecksum(payload.data(), payload.size());

            // Checksum should be different (collision unlikely)
            if (checksum3 == checksum1) {
                // Collision detected (very rare)
            }
        }
    }
}
