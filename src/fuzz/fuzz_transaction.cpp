// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzzing harness for CTransaction deserialization
 *
 * This fuzzer tests the robustness of transaction deserialization by feeding
 * random byte sequences to CTransaction::Deserialize(). It aims to discover:
 * - Memory corruption bugs (buffer overflows, out-of-bounds reads)
 * - Integer overflows in size calculations
 * - Null pointer dereferences
 * - Assertion failures on malformed input
 * - Memory leaks in error paths
 *
 * Build with:
 *   make fuzz_transaction FUZZER=1
 *
 * Run with:
 *   ./fuzz_transaction -max_total_time=3600 fuzz_corpus/transaction/
 */

#include <primitives/transaction.h>
#include <stdint.h>
#include <stddef.h>
#include <string>

/**
 * libFuzzer entry point
 * Called for each fuzzer-generated input
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Reject inputs that are too large (> 1MB)
    // This prevents timeouts on pathological inputs
    if (size > 1000000) {
        return 0;
    }

    // Attempt to deserialize transaction from raw bytes
    CTransaction tx;
    std::string error;
    size_t bytes_consumed = 0;

    bool success = tx.Deserialize(data, size, &error, &bytes_consumed);

    // If deserialization succeeded, exercise additional methods
    if (success) {
        // Exercise hash calculation
        // This tests the serialization -> hash pipeline
        try {
            uint256 hash = tx.GetHash();
            (void)hash;  // Suppress unused variable warning
        } catch (...) {
            // Catch any exceptions from GetHash
            return 0;
        }

        // Exercise basic structure validation
        // This tests internal consistency checks
        try {
            bool valid = tx.CheckBasicStructure();
            (void)valid;
        } catch (...) {
            // Catch any exceptions
            return 0;
        }

        // Exercise size calculation
        try {
            size_t serialized_size = tx.GetSerializedSize();
            (void)serialized_size;
        } catch (...) {
            // Catch any exceptions
            return 0;
        }

        // Exercise IsCoinBase check
        try {
            bool is_coinbase = tx.IsCoinBase();
            (void)is_coinbase;
        } catch (...) {
            // Catch any exceptions
            return 0;
        }

        // Exercise GetValueOut (can throw on overflow)
        try {
            uint64_t value_out = tx.GetValueOut();
            (void)value_out;
        } catch (const std::runtime_error&) {
            // Expected exception for overflow
            return 0;
        } catch (...) {
            // Catch any other exceptions
            return 0;
        }

        // Exercise re-serialization
        // This tests that deserialized data can be re-serialized
        try {
            std::vector<uint8_t> reserialized = tx.Serialize();
            (void)reserialized;
        } catch (...) {
            // Catch any exceptions
            return 0;
        }

        // If we have inputs and outputs, exercise iteration
        if (!tx.vin.empty()) {
            try {
                for (const auto& input : tx.vin) {
                    // Access prevout
                    (void)input.prevout.hash;
                    (void)input.prevout.n;
                    (void)input.prevout.IsNull();

                    // Access scriptSig
                    (void)input.scriptSig.size();

                    // Access sequence
                    (void)input.nSequence;
                }
            } catch (...) {
                return 0;
            }
        }

        if (!tx.vout.empty()) {
            try {
                for (const auto& output : tx.vout) {
                    // Access value
                    (void)output.nValue;

                    // Access scriptPubKey
                    (void)output.scriptPubKey.size();
                }
            } catch (...) {
                return 0;
            }
        }
    }

    // Fuzzer expects 0 return value
    return 0;
}

/**
 * Optional: Custom initialization
 * Called once before fuzzing starts
 */
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    // No special initialization needed
    return 0;
}
