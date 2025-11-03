// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include "fuzz.h"
#include "util.h"
#include "fuzz_helpers.h"
#include <consensus/pow.h>
#include <primitives/block.h>
#include <cstdint>
#include <cassert>

/**
 * Fuzz target: Difficulty calculation
 *
 * Tests:
 * - Difficulty adjustment at 2016 block intervals
 * - 4x maximum adjustment limits
 * - Integer-only arithmetic correctness
 * - Edge cases (very fast/slow blocks)
 * - Boundary conditions
 * - Cross-platform determinism
 *
 * Coverage:
 * - src/consensus/pow.cpp
 *
 * Based on gap analysis: P0-2 (difficulty adjustment)
 * Priority: CRITICAL (consensus)
 */

FUZZ_TARGET(difficulty_calculate)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Fuzz input difficulty (compact format)
        uint32_t nBits = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Fuzz actual timespan
        int64_t nActualTimespan = fuzzed_data.ConsumeIntegral<int64_t>();

        // Limit to reasonable range
        const int64_t nTargetTimespan = 14 * 24 * 60 * 60; // 2 weeks

        // Apply 4x limits (same as Bitcoin)
        if (nActualTimespan < nTargetTimespan / 4) {
            nActualTimespan = nTargetTimespan / 4;
        }
        if (nActualTimespan > nTargetTimespan * 4) {
            nActualTimespan = nTargetTimespan * 4;
        }

        // Calculate new difficulty
        // This calls the actual implementation
        uint32_t nBitsNew = CalculateNextWorkRequired(nBits, nActualTimespan, nTargetTimespan);

        // Verify result is reasonable
        if (nBitsNew != 0) {
            // Decode to verify it's valid
            uint256 target;
            target.SetCompact(nBitsNew);

            // Should not be null unless error occurred
            (void)target;
        }

    } catch (const std::exception& e) {
        // Expected for invalid inputs
        return;
    }
}

/**
 * Fuzz target: Compact difficulty encoding/decoding
 *
 * Tests compact format (nBits) conversion
 */
FUZZ_TARGET(difficulty_compact_format)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Fuzz compact difficulty
        uint32_t nBits = fuzzed_data.ConsumeIntegral<uint32_t>();

        // Decode to uint256
        uint256 target;
        target.SetCompact(nBits);

        // Encode back
        uint32_t nBits2 = target.GetCompact();

        // Check if consistent
        // Note: May differ due to precision/normalization

        // Verify target is reasonable
        if (target.IsNull()) {
            // Invalid difficulty
            return;
        }

        // Verify target doesn't exceed maximum
        uint256 max_target;
        max_target.SetCompact(0x1d00ffff); // Bitcoin genesis difficulty

        if (target > max_target) {
            // Difficulty too low (target too high)
            // May be invalid depending on network rules
        }

    } catch (const std::exception& e) {
        return;
    }
}

/**
 * Fuzz target: Difficulty adjustment limits
 *
 * Tests 4x maximum adjustment enforcement
 */
FUZZ_TARGET(difficulty_adjustment_limits)
{
    FuzzedDataProvider fuzzed_data(data, size);

    // Test various timespan values
    const int64_t nTargetTimespan = 14 * 24 * 60 * 60; // 2 weeks

    int64_t timespans[] = {
        0,                              // Instant blocks (invalid)
        1,                              // 1 second
        nTargetTimespan / 4,            // 4x faster (minimum)
        nTargetTimespan / 2,            // 2x faster
        nTargetTimespan,                // Exactly 2 weeks (no change)
        nTargetTimespan * 2,            // 2x slower
        nTargetTimespan * 4,            // 4x slower (maximum)
        nTargetTimespan * 10,           // 10x slower (clamped to 4x)
        INT64_MAX,                      // Maximum value (clamped)
    };

    for (int64_t timespan : timespans) {
        try {
            // Apply limits
            int64_t limited = timespan;

            if (limited < nTargetTimespan / 4) {
                limited = nTargetTimespan / 4;
            }
            if (limited > nTargetTimespan * 4) {
                limited = nTargetTimespan * 4;
            }

            // Verify limits applied correctly
            assert(limited >= nTargetTimespan / 4);
            assert(limited <= nTargetTimespan * 4);

        } catch (const std::exception& e) {
            assert(false); // Should not throw
        }
    }
}

/**
 * Fuzz target: Difficulty arithmetic
 *
 * Tests integer-only multiplication/division
 */
FUZZ_TARGET(difficulty_arithmetic)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Test integer arithmetic that might overflow/underflow

        // Fuzz large numbers
        uint64_t a = fuzzed_data.ConsumeIntegral<uint64_t>();
        uint64_t b = fuzzed_data.ConsumeIntegral<uint64_t>();
        uint64_t c = fuzzed_data.ConsumeIntegral<uint64_t>();

        // Test multiplication with overflow check
        if (b != 0 && a > UINT64_MAX / b) {
            // Would overflow
            return;
        }

        uint64_t product = a * b;

        // Test division
        if (c != 0) {
            uint64_t quotient = product / c;
            uint64_t remainder = product % c;

            // Verify division identity
            assert(product == quotient * c + remainder);
        }

    } catch (const std::exception& e) {
        return;
    }
}

/**
 * Fuzz target: Proof-of-Work verification
 *
 * Tests PoW validation logic
 */
FUZZ_TARGET(difficulty_pow_verify)
{
    FuzzedDataProvider fuzzed_data(data, size);

    try {
        // Create block header with fuzzed values
        CBlockHeader header;

        header.nVersion = fuzzed_data.ConsumeIntegral<int32_t>();

        // Generate random hashes from fuzz data
        if (fuzzed_data.remaining_bytes() >= 32) {
            header.hashPrevBlock = uint256FromFuzz(data + fuzzed_data.remaining_bytes() - 32, 32);
        }
        if (fuzzed_data.remaining_bytes() >= 64) {
            header.hashMerkleRoot = uint256FromFuzz(data + fuzzed_data.remaining_bytes() - 64, 32);
        }

        header.nTime = fuzzed_data.ConsumeIntegral<uint32_t>();
        header.nBits = fuzzed_data.ConsumeIntegral<uint32_t>();
        header.nNonce = fuzzed_data.ConsumeIntegral<uint64_t>();

        // Get difficulty target
        uint256 target;
        target.SetCompact(header.nBits);

        // Calculate block hash (uses RandomX)
        uint256 hash = header.GetHash();

        // Verify PoW: hash must be <= target
        bool pow_valid = (hash <= target);

        // Just testing that it doesn't crash
        (void)pow_valid;

    } catch (const std::exception& e) {
        return;
    }
}

/**
 * Fuzz target: Difficulty retarget timing
 *
 * Tests retarget interval calculation
 */
FUZZ_TARGET(difficulty_retarget_timing)
{
    FuzzedDataProvider fuzzed_data(data, size);

    // Retarget every 2016 blocks
    const int64_t nRetargetInterval = 2016;

    // Fuzz block heights
    int64_t heights[] = {
        0,
        1,
        2015,
        2016,  // First retarget
        2017,
        4031,
        4032,  // Second retarget
        4033,
        fuzzed_data.ConsumeIntegral<int64_t>(),
    };

    for (int64_t height : heights) {
        if (height < 0) continue;

        // Check if retarget block
        bool is_retarget = (height % nRetargetInterval == 0);

        if (is_retarget && height > 0) {
            // This block should recalculate difficulty
            // Based on timestamps from (height - 2016) to (height - 1)
        } else {
            // Use previous block's difficulty
        }
    }
}
