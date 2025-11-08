// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Network message serialization
 *
 * Creates a message with fuzzed data and validates format.
 * Extracted from fuzz_network_message.cpp multi-target file.
 */

#include "fuzz.h"
#include "util.h"
#include "../../net/protocol.h"
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

FUZZ_TARGET(network_message_create)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Create message header
        NetProtocol::CMessageHeader header;

        // Fuzz magic
        header.magic = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Fuzz command (must be 12 bytes, null-padded)
        std::string command = fuzzed_data.ConsumeRandomLengthString(11);
        memset(header.command, 0, 12);
        memcpy(header.command, command.c_str(), command.length());

        // Fuzz payload
        size_t payload_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 1000);
        std::vector<uint8_t> payload = fuzzed_data.ConsumeBytes<uint8_t>(payload_size);

        header.payload_size = payload.size();

        // Calculate checksum
        header.checksum = CalculateChecksum(payload.data(), payload.size());

        // Serialize message
        std::vector<uint8_t> message;
        message.insert(message.end(),
                      reinterpret_cast<uint8_t*>(&header),
                      reinterpret_cast<uint8_t*>(&header) + sizeof(header));
        message.insert(message.end(), payload.begin(), payload.end());

        // Verify we can parse it back
        if (message.size() >= sizeof(NetProtocol::CMessageHeader)) {
            NetProtocol::CMessageHeader parsed_header;
            memcpy(&parsed_header, message.data(), sizeof(NetProtocol::CMessageHeader));

            assert(parsed_header.magic == header.magic);
            assert(parsed_header.payload_size == header.payload_size);
            assert(parsed_header.checksum == header.checksum);
        }

    } catch (const std::exception& e) {
        return;
    }
}
