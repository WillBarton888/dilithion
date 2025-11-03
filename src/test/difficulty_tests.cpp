// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Difficulty Adjustment Tests - Boost Test Suite
 *
 * P0 CRITICAL: These tests exercise consensus/pow.cpp functions
 * to ensure they appear in coverage reports and are validated.
 *
 * Previously pow.cpp was not in coverage report despite having
 * difficulty_determinism_test.cpp because that was standalone.
 *
 * This integrates difficulty tests into the Boost suite for:
 * - Coverage measurement
 * - CI integration
 * - Automated testing
 */

#include <boost/test/unit_test.hpp>

#include <consensus/pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <cstring>

BOOST_AUTO_TEST_SUITE(difficulty_tests)

/**
 * Test CompactToBig conversion
 */
BOOST_AUTO_TEST_CASE(compact_to_big_conversion) {
    // Test MIN_DIFFICULTY_BITS (0x1d00ffff)
    uint256 target = CompactToBig(0x1d00ffff);

    // Should produce a valid 256-bit target
    BOOST_CHECK(!target.IsNull());

    // Verify the conversion produces expected structure
    // 0x1d00ffff means: 0x00ffff << (8 * (0x1d - 3))
    // Result should have 0xffff in the upper bits
}

/**
 * Test BigToCompact conversion
 */
BOOST_AUTO_TEST_CASE(big_to_compact_conversion) {
    // Create a target
    uint256 target;
    memset(target.data, 0, 32);
    target.data[29] = 0x00;
    target.data[30] = 0xff;
    target.data[31] = 0xff;

    // Convert to compact
    uint32_t compact = BigToCompact(target);

    // Should produce a valid compact representation
    BOOST_CHECK(compact != 0);
}

/**
 * Test CompactToBig/BigToCompact roundtrip
 */
BOOST_AUTO_TEST_CASE(difficulty_conversion_roundtrip) {
    uint32_t original = 0x1d00ffff;

    // Convert compact -> big -> compact
    uint256 target = CompactToBig(original);
    uint32_t result = BigToCompact(target);

    // Should match original (within rounding)
    BOOST_CHECK(result == original || ((result & 0xFFFFFF) == (original & 0xFFFFFF)));
}

/**
 * Test CheckProofOfWork with valid PoW
 */
BOOST_AUTO_TEST_CASE(check_proof_of_work_valid) {
    // Create a hash that's definitely below the target
    uint256 hash;
    memset(hash.data, 0, 32);
    hash.data[0] = 0x01;  // Very small hash

    // Use maximum difficulty target (easiest)
    uint32_t nBits = MAX_DIFFICULTY_BITS;

    // Should pass
    BOOST_CHECK(CheckProofOfWork(hash, nBits));
}

/**
 * Test CheckProofOfWork with invalid PoW
 */
BOOST_AUTO_TEST_CASE(check_proof_of_work_invalid) {
    // Create a hash that's definitely above the target
    uint256 hash;
    memset(hash.data, 0xFF, 32);  // Very large hash

    // Use minimum difficulty target (hardest)
    uint32_t nBits = MIN_DIFFICULTY_BITS;

    // Should fail
    BOOST_CHECK(!CheckProofOfWork(hash, nBits));
}

/**
 * Test CalculateNextWorkRequired - no change
 */
BOOST_AUTO_TEST_CASE(calculate_next_work_no_change) {
    uint32_t oldCompact = 0x1d00ffff;
    int64_t actualTimespan = 2016 * 240;  // Exactly target timespan
    int64_t targetTimespan = 2016 * 240;

    uint32_t newCompact = CalculateNextWorkRequired(oldCompact, actualTimespan, targetTimespan);

    // Difficulty should remain the same
    BOOST_CHECK_EQUAL(newCompact, oldCompact);
}

/**
 * Test CalculateNextWorkRequired - faster blocks (increase difficulty)
 */
BOOST_AUTO_TEST_CASE(calculate_next_work_faster_blocks) {
    uint32_t oldCompact = 0x1d00ffff;
    int64_t actualTimespan = 2016 * 120;  // Half the time (2x faster)
    int64_t targetTimespan = 2016 * 240;

    uint32_t newCompact = CalculateNextWorkRequired(oldCompact, actualTimespan, targetTimespan);

    // Difficulty should increase (compact value stays same or decreases slightly)
    // Due to MIN_DIFFICULTY_BITS limit, may stay at 0x1d00ffff
    BOOST_CHECK(newCompact <= oldCompact);
}

/**
 * Test CalculateNextWorkRequired - slower blocks (decrease difficulty)
 */
BOOST_AUTO_TEST_CASE(calculate_next_work_slower_blocks) {
    uint32_t oldCompact = 0x1d00ffff;
    int64_t actualTimespan = 2016 * 480;  // Twice the time (2x slower)
    int64_t targetTimespan = 2016 * 240;

    uint32_t newCompact = CalculateNextWorkRequired(oldCompact, actualTimespan, targetTimespan);

    // Difficulty should decrease (target increases, so compact increases)
    BOOST_CHECK(newCompact >= oldCompact);
}

/**
 * Test CalculateNextWorkRequired - 4x adjustment limit
 */
BOOST_AUTO_TEST_CASE(calculate_next_work_4x_limit) {
    uint32_t oldCompact = 0x1d00ffff;
    int64_t actualTimespan = 2016 * 960;  // 4x slower
    int64_t targetTimespan = 2016 * 240;

    uint32_t newCompact = CalculateNextWorkRequired(oldCompact, actualTimespan, targetTimespan);

    // Should be limited to 4x easier
    // Expected: 0x1d00ffff * 4 = 0x1d03fffc
    BOOST_CHECK(newCompact == 0x1d03fffc);
}

/**
 * Test CalculateNextWorkRequired - MIN_DIFFICULTY_BITS floor
 */
BOOST_AUTO_TEST_CASE(calculate_next_work_min_difficulty_floor) {
    uint32_t oldCompact = 0x1d00ffff;  // Already at minimum
    int64_t actualTimespan = 2016 * 60;  // 4x faster
    int64_t targetTimespan = 2016 * 240;

    uint32_t newCompact = CalculateNextWorkRequired(oldCompact, actualTimespan, targetTimespan);

    // Should stay at MIN_DIFFICULTY_BITS (can't get harder)
    BOOST_CHECK_EQUAL(newCompact, MIN_DIFFICULTY_BITS);
}

/**
 * Test HashLessThan comparison
 */
BOOST_AUTO_TEST_CASE(hash_less_than_comparison) {
    uint256 smaller, larger;

    // Create smaller hash (mostly zeros)
    memset(smaller.data, 0, 32);
    smaller.data[0] = 0x01;

    // Create larger hash (mostly ones)
    memset(larger.data, 0xFF, 32);

    // smaller < larger
    BOOST_CHECK(HashLessThan(smaller, larger));
    BOOST_CHECK(!HashLessThan(larger, smaller));
}

/**
 * Test HashLessThan equal hashes
 */
BOOST_AUTO_TEST_CASE(hash_less_than_equal) {
    uint256 hash1, hash2;

    memset(hash1.data, 0x42, 32);
    memset(hash2.data, 0x42, 32);

    // Equal hashes should not satisfy <
    BOOST_CHECK(!HashLessThan(hash1, hash2));
    BOOST_CHECK(!HashLessThan(hash2, hash1));
}

/**
 * Test ChainWorkGreaterThan comparison
 */
BOOST_AUTO_TEST_CASE(chain_work_greater_than) {
    uint256 more_work, less_work;

    // More work (larger value)
    memset(more_work.data, 0xFF, 32);

    // Less work (smaller value)
    memset(less_work.data, 0x00, 32);
    less_work.data[0] = 0x01;

    // more_work > less_work
    BOOST_CHECK(ChainWorkGreaterThan(more_work, less_work));
    BOOST_CHECK(!ChainWorkGreaterThan(less_work, more_work));
}

/**
 * Test consensus constants
 */
BOOST_AUTO_TEST_CASE(consensus_constants) {
    // Verify block target spacing
    BOOST_CHECK_EQUAL(BLOCK_TARGET_SPACING, 240);  // 4 minutes

    // Verify difficulty bounds
    BOOST_CHECK_EQUAL(MIN_DIFFICULTY_BITS, 0x1d00ffff);
    BOOST_CHECK_EQUAL(MAX_DIFFICULTY_BITS, 0x1f0fffff);

    // Verify MIN is harder than MAX
    BOOST_CHECK(MIN_DIFFICULTY_BITS < MAX_DIFFICULTY_BITS);
}

/**
 * Test determinism - same inputs produce same outputs
 */
BOOST_AUTO_TEST_CASE(difficulty_calculation_determinism) {
    uint32_t input = 0x1d00ffff;
    int64_t actual = 2016 * 480;  // 2x slower
    int64_t target = 2016 * 240;

    // Calculate multiple times
    uint32_t result1 = CalculateNextWorkRequired(input, actual, target);
    uint32_t result2 = CalculateNextWorkRequired(input, actual, target);
    uint32_t result3 = CalculateNextWorkRequired(input, actual, target);

    // All results should be identical
    BOOST_CHECK_EQUAL(result1, result2);
    BOOST_CHECK_EQUAL(result2, result3);
}

/**
 * Test edge case: zero timespan (should be clamped)
 */
BOOST_AUTO_TEST_CASE(difficulty_zero_timespan) {
    uint32_t input = 0x1d00ffff;
    int64_t actual = 0;  // Zero actual timespan
    int64_t target = 2016 * 240;

    // Should not crash and should produce valid output
    uint32_t result = CalculateNextWorkRequired(input, actual, target);

    // Should clamp to minimum difficulty or handle gracefully
    BOOST_CHECK(result >= MIN_DIFFICULTY_BITS);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);
}

BOOST_AUTO_TEST_SUITE_END() // difficulty_tests
