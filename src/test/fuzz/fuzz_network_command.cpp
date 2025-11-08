// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Network message command parsing
 *
 * Tests command string handling and validation.
 * Extracted from fuzz_network_message.cpp multi-target file.
 */

#include "fuzz.h"
#include "util.h"
#include <cassert>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

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
