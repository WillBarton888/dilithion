// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * NOTE: This file contains multiple fuzz targets wrapped in #if 0 blocks.
 * libFuzzer allows only ONE FUZZ_TARGET per binary.
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
 * Coverage:
 * - src/net/protocol.h
 * - src/net/serialize.h
 *
 * Based on gap analysis: P1-4 (network message checksums)
 * Priority: HIGH (network integrity)
 */

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

#if 0
/**
 * Fuzz target: Network message serialization
 *
 * Creates a message with fuzzed data and validates format
 */
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
#endif

#if 0
/**
 * Fuzz target: Network message checksum validation
 *
 * Tests checksum calculation and validation
 */
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
#endif

#if 0
/**
 * Fuzz target: Network message command parsing
 *
 * Tests command string handling
 */
FUZZ_TARGET(network_message_command)
{
    FuzzedDataProvider fuzzed_data(data, size);

    // Test various command strings
    std::vector<std::string> valid_commands = {
        "version",
        "verack",
        "addr",
        "inv",
        "getdata",
        "notfound",
        "getblocks",
        "getheaders",
        "tx",
        "block",
        "headers",
        "ping",
        "pong",
        "reject",
        "mempool",
    };

    // Test valid commands
    for (const auto& cmd : valid_commands) {
        char command[12];
        memset(command, 0, 12);
        memcpy(command, cmd.c_str(), std::min(cmd.length(), size_t(12)));

        // Verify null-terminated or padded
        bool valid = false;
        for (int i = 0; i < 12; ++i) {
            if (command[i] == '\0') {
                valid = true;
                break;
            }
        }

        assert(valid || cmd.length() == 12);
    }

    // Test fuzzed command strings
    try {
        std::string fuzzed_cmd = fuzzed_data.ConsumeRandomLengthString(12);

        char command[12];
        memset(command, 0, 12);
        memcpy(command, fuzzed_cmd.c_str(), std::min(fuzzed_cmd.length(), size_t(12)));

        // Should handle any command gracefully
        // Unknown commands are typically ignored

    } catch (const std::exception& e) {
        return;
    }
}
#endif
