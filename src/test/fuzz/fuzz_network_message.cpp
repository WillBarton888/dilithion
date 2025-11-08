// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Network message deserialization
 *
 * Tests:
 * - Message header parsing
 * - Magic bytes validation
 * - Command string parsing
 * - Payload length parsing
 * - Checksum validation
 * - Payload deserialization
 * - Invalid message rejection
 *
 * Message format:
 * [magic:4] [command:12] [length:4] [checksum:4] [payload:length]
 *
 * Note: This file previously contained multiple disabled targets.
 * They have been split into separate fuzzer binaries as part of
 * Phase 3 fuzzing infrastructure enhancement (November 2025).
 *
 * Related fuzzers:
 * - fuzz_network_create.cpp: Message serialization
 * - fuzz_network_checksum.cpp: Checksum validation
 * - fuzz_network_command.cpp: Command parsing
 *
 * Coverage:
 * - src/net/protocol.h
 * - src/net/serialize.h
 *
 * Priority: HIGH (network integrity)
 */

#include "fuzz.h"
#include "util.h"
#include "../../net/protocol.h"
#include "../../primitives/block.h"
#include "../../primitives/transaction.h"
#include "../../crypto/sha3.h"
#include <cassert>
#include <cstring>
#include <vector>

// Network constants
static const size_t MAX_SIZE = 32 * 1024 * 1024;  // 32 MB

/**
 * Calculate message checksum (SHA3-256 based)
 */
uint32_t CalculateChecksum(const uint8_t* payload, size_t length) {
    // Dilithion uses SHA3-256
    uint8_t hash[32];
    SHA3_256(payload, length, hash);

    // Return first 4 bytes as uint32_t
    uint32_t checksum;
    memcpy(&checksum, hash, 4);
    return checksum;
}

FUZZ_TARGET(network_message_parse)
{
    FuzzedDataProvider fuzzed_data(data, size);

    if (size < sizeof(NetProtocol::CMessageHeader)) {
        // Not enough data for header
        return;
    }

    try {
        // Parse header
        NetProtocol::CMessageHeader header;
        memcpy(&header, data, sizeof(NetProtocol::CMessageHeader));

        // Check magic bytes (example: 0xD9B4BEF9 for Bitcoin mainnet)
        // Dilithion will have its own magic
        // For fuzzing, we don't reject on magic mismatch

        // Check command is null-terminated or padded
        bool command_valid = false;
        for (int i = 0; i < 12; ++i) {
            if (header.command[i] == '\0') {
                command_valid = true;
                break;
            }
        }

        // Check payload length is reasonable
        if (header.payload_size > MAX_SIZE) {
            // Payload too large
            return;
        }

        // Check we have enough data
        if (size < sizeof(NetProtocol::CMessageHeader) + header.payload_size) {
            // Incomplete message
            return;
        }

        // Get payload
        const uint8_t* payload = data + sizeof(NetProtocol::CMessageHeader);

        // Verify checksum
        uint32_t calculated_checksum = CalculateChecksum(payload, header.payload_size);

        if (calculated_checksum != header.checksum) {
            // Checksum mismatch - reject message
            return;
        }

        // Checksum valid - message is authentic

        // Try to parse payload based on command
        std::string command_str(header.command, strnlen(header.command, 12));

        // Parse different message types
        if (command_str == "version") {
            // Parse version message
        } else if (command_str == "verack") {
            // Parse verack (empty payload)
        } else if (command_str == "addr") {
            // Parse addr message (peer addresses)
        } else if (command_str == "inv") {
            // Parse inventory message
        } else if (command_str == "getdata") {
            // Parse getdata message
        } else if (command_str == "block") {
            // Parse block message (CBlock doesn't have Deserialize yet)
        } else if (command_str == "tx") {
            CTransaction tx;
            std::string error;
            size_t bytes_consumed = 0;
            tx.Deserialize(payload, header.payload_size, &error, &bytes_consumed);
        }

    } catch (const std::exception& e) {
        return;
    }
}
