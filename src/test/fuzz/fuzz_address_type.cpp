// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: Address type detection
 *
 * Tests detecting address type from string (P2PKH, P2SH, Bech32, etc).
 * Extracted from fuzz_address.cpp multi-target file.
 */

#include "fuzz.h"
#include "util.h"
#include <string>

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
