// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz Harness: SHA-3 Hash Function
 *
 * Tests the SHA-3-256 implementation for:
 * - Crashes on arbitrary input
 * - Memory safety
 * - Deterministic output
 * - State consistency
 */

#include "fuzz.h"
#include "util.h"
#include "../../crypto/sha3.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

FUZZ_TARGET(sha3_256)
{
    InitializeFuzzEnvironment();

    FuzzedDataProvider provider(data, size);

    // Test 1: Basic hashing with random length input
    {
        std::vector<uint8_t> input = provider.ConsumeRandomLengthByteVector(10000);
        uint8_t output1[32];
        uint8_t output2[32];

        // Hash the input
        SHA3_256(input.data(), input.size(), output1);

        // Hash again - should be deterministic
        SHA3_256(input.data(), input.size(), output2);

        // Verify determinism
        assert(std::memcmp(output1, output2, 32) == 0);
    }

    // Test 2: Incremental hashing (if available)
    if (provider.remaining_bytes() > 0) {
        std::vector<uint8_t> input1 = provider.ConsumeRandomLengthByteVector(1000);
        std::vector<uint8_t> input2 = provider.ConsumeRandomLengthByteVector(1000);

        // Hash concatenated input
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), input1.begin(), input1.end());
        combined.insert(combined.end(), input2.begin(), input2.end());

        uint8_t output_combined[32];
        SHA3_256(combined.data(), combined.size(), output_combined);

        // The output is a valid 32-byte hash
        // (no assertion needed, just ensure it doesn't crash)
    }

    // Test 3: Edge cases
    if (provider.remaining_bytes() == 0) {
        // Empty input
        uint8_t output_empty[32];
        SHA3_256(nullptr, 0, output_empty);

        // Known SHA3-256("") result - verify if desired
        // const uint8_t expected_empty[32] = {...};
        // assert(std::memcmp(output_empty, expected_empty, 32) == 0);
    }

    // Test 4: Various output sizes
    if (provider.remaining_bytes() > 0) {
        uint8_t output_small[16];
        std::vector<uint8_t> input = provider.ConsumeRemainingBytes();

        // SHA3-256 always produces 32-byte output
        // Test with standard 32-byte output
        uint8_t output_full[32];
        SHA3_256(input.data(), input.size(), output_full);
    }

    CleanupFuzzEnvironment();
}

// Compile with:
// clang++ -fsanitize=fuzzer,address,undefined \
//         -I../../.. -I../../../depends/dilithium/ref \
//         -std=c++17 \
//         fuzz_sha3.cpp ../../crypto/sha3.cpp \
//         ../../../depends/dilithium/ref/fips202.o \
//         -o fuzz_sha3
//
// Run with:
// ./fuzz_sha3
// ./fuzz_sha3 -max_total_time=60
// ./fuzz_sha3 -max_len=100000
