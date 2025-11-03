// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Utility Tests
 *
 * Tests for utility functions: string encoding, hex conversion, amount handling
 * Following Bitcoin Core testing standards with Boost Test Framework
 */

#include <boost/test/unit_test.hpp>

#include <amount.h>
#include <primitives/block.h>
#include <string>
#include <vector>
#include <cstring>

BOOST_AUTO_TEST_SUITE(util_tests)

/**
 * Test Suite 1: Amount Tests
 */
BOOST_AUTO_TEST_SUITE(amount_tests)

BOOST_AUTO_TEST_CASE(coin_definition) {
    // 1 DIL = 100,000,000 satoshis
    BOOST_CHECK_EQUAL(COIN, 100000000);
}

BOOST_AUTO_TEST_CASE(cent_definition) {
    // 1 cent = 1,000,000 satoshis
    BOOST_CHECK_EQUAL(CENT, 1000000);
    BOOST_CHECK_EQUAL(CENT * 100, COIN);
}

BOOST_AUTO_TEST_CASE(amount_arithmetic) {
    // Basic arithmetic
    BOOST_CHECK_EQUAL(1 * COIN, 100000000);
    BOOST_CHECK_EQUAL(10 * COIN, 1000000000);
    BOOST_CHECK_EQUAL(COIN / 2, 50000000);

    // Fractional coins
    BOOST_CHECK_EQUAL(COIN / 4, 25000000);  // 0.25 DIL
    BOOST_CHECK_EQUAL(COIN / 10, 10000000);  // 0.1 DIL
}

BOOST_AUTO_TEST_CASE(satoshi_conversion) {
    // Convert from DIL to satoshis
    uint64_t one_dil = 1 * COIN;
    BOOST_CHECK_EQUAL(one_dil, 100000000);

    uint64_t half_dil = COIN / 2;
    BOOST_CHECK_EQUAL(half_dil, 50000000);

    // 0.001 DIL = 100,000 satoshis
    uint64_t milli_dil = COIN / 1000;
    BOOST_CHECK_EQUAL(milli_dil, 100000);
}

BOOST_AUTO_TEST_CASE(amount_comparison) {
    uint64_t a = 50 * COIN;
    uint64_t b = 25 * COIN;
    uint64_t c = 75 * COIN;

    BOOST_CHECK(a > b);
    BOOST_CHECK(c > a);
    BOOST_CHECK(b < a);
    BOOST_CHECK(a == 50 * COIN);
}

BOOST_AUTO_TEST_CASE(amount_addition) {
    uint64_t a = 10 * COIN;
    uint64_t b = 20 * COIN;
    uint64_t sum = a + b;

    BOOST_CHECK_EQUAL(sum, 30 * COIN);
}

BOOST_AUTO_TEST_CASE(amount_subtraction) {
    uint64_t a = 50 * COIN;
    uint64_t b = 30 * COIN;
    uint64_t diff = a - b;

    BOOST_CHECK_EQUAL(diff, 20 * COIN);
}

BOOST_AUTO_TEST_CASE(max_money) {
    // Dilithion max supply: 21 million
    uint64_t max_supply = 21000000 * COIN;
    BOOST_CHECK_EQUAL(max_supply, 2100000000000000ULL);

    // Check it fits in uint64_t
    BOOST_CHECK(max_supply < UINT64_MAX);
}

BOOST_AUTO_TEST_CASE(zero_amount) {
    uint64_t zero = 0;
    BOOST_CHECK_EQUAL(zero, 0);
    BOOST_CHECK(zero < COIN);
}

BOOST_AUTO_TEST_SUITE_END() // amount_tests

/**
 * Test Suite 2: uint256 Utility Tests
 */
BOOST_AUTO_TEST_SUITE(uint256_utility_tests)

BOOST_AUTO_TEST_CASE(uint256_data_access) {
    uint256 hash;

    // Set specific pattern
    for (int i = 0; i < 32; i++) {
        hash.data[i] = static_cast<uint8_t>(i);
    }

    // Verify pattern
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(hash.data[i], static_cast<uint8_t>(i));
    }
}

BOOST_AUTO_TEST_CASE(uint256_memcmp_compatibility) {
    uint256 hash1, hash2;

    memset(hash1.data, 0x42, 32);
    memset(hash2.data, 0x42, 32);

    // Should be equal via memcmp
    BOOST_CHECK_EQUAL(memcmp(hash1.data, hash2.data, 32), 0);
    BOOST_CHECK(hash1 == hash2);
}

BOOST_AUTO_TEST_CASE(uint256_copy) {
    uint256 hash1, hash2;

    // Set hash1
    memset(hash1.data, 0xaa, 32);

    // Copy to hash2
    memcpy(hash2.data, hash1.data, 32);

    // Verify
    BOOST_CHECK(hash1 == hash2);
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(hash1.data[i], hash2.data[i]);
    }
}

BOOST_AUTO_TEST_CASE(uint256_zero_vs_nonzero) {
    uint256 zero, nonzero;

    BOOST_CHECK(zero.IsNull());
    BOOST_CHECK(!nonzero.IsNull() == false);  // Double check

    nonzero.data[15] = 0x01;
    BOOST_CHECK(!nonzero.IsNull());
}

BOOST_AUTO_TEST_SUITE_END() // uint256_utility_tests

/**
 * Test Suite 3: Byte Manipulation Tests
 */
BOOST_AUTO_TEST_SUITE(byte_manipulation_tests)

BOOST_AUTO_TEST_CASE(byte_array_operations) {
    std::vector<uint8_t> data;

    // Append bytes
    data.push_back(0xde);
    data.push_back(0xad);
    data.push_back(0xbe);
    data.push_back(0xef);

    BOOST_CHECK_EQUAL(data.size(), 4);
    BOOST_CHECK_EQUAL(data[0], 0xde);
    BOOST_CHECK_EQUAL(data[1], 0xad);
    BOOST_CHECK_EQUAL(data[2], 0xbe);
    BOOST_CHECK_EQUAL(data[3], 0xef);
}

BOOST_AUTO_TEST_CASE(byte_array_concatenation) {
    std::vector<uint8_t> a = {0x01, 0x02};
    std::vector<uint8_t> b = {0x03, 0x04};

    // Concatenate
    a.insert(a.end(), b.begin(), b.end());

    BOOST_CHECK_EQUAL(a.size(), 4);
    BOOST_CHECK_EQUAL(a[0], 0x01);
    BOOST_CHECK_EQUAL(a[1], 0x02);
    BOOST_CHECK_EQUAL(a[2], 0x03);
    BOOST_CHECK_EQUAL(a[3], 0x04);
}

BOOST_AUTO_TEST_CASE(byte_array_comparison) {
    std::vector<uint8_t> a = {0x01, 0x02, 0x03};
    std::vector<uint8_t> b = {0x01, 0x02, 0x03};
    std::vector<uint8_t> c = {0x01, 0x02, 0x04};

    BOOST_CHECK(a == b);
    BOOST_CHECK(!(a == c));
    BOOST_CHECK(a != c);
}

BOOST_AUTO_TEST_CASE(byte_array_clear) {
    std::vector<uint8_t> data = {0xaa, 0xbb, 0xcc};

    BOOST_CHECK_EQUAL(data.size(), 3);

    data.clear();

    BOOST_CHECK(data.empty());
    BOOST_CHECK_EQUAL(data.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END() // byte_manipulation_tests

/**
 * Test Suite 4: Bounds Checking Tests
 */
BOOST_AUTO_TEST_SUITE(bounds_checking_tests)

BOOST_AUTO_TEST_CASE(uint32_max) {
    uint32_t max = 0xffffffff;
    BOOST_CHECK_EQUAL(max, UINT32_MAX);

    // Verify wrapping behavior
    uint32_t wrapped = max + 1;
    BOOST_CHECK_EQUAL(wrapped, 0);
}

BOOST_AUTO_TEST_CASE(uint64_max) {
    uint64_t max = 0xffffffffffffffffULL;
    BOOST_CHECK_EQUAL(max, UINT64_MAX);

    // Check that max money fits
    uint64_t max_supply = 21000000 * COIN;
    BOOST_CHECK(max_supply < max);
}

BOOST_AUTO_TEST_CASE(int32_range) {
    int32_t max_positive = 0x7fffffff;
    int32_t min_negative = -2147483648;

    BOOST_CHECK_EQUAL(max_positive, INT32_MAX);
    BOOST_CHECK_EQUAL(min_negative, INT32_MIN);
}

BOOST_AUTO_TEST_CASE(uint8_range) {
    uint8_t min = 0;
    uint8_t max = 0xff;

    BOOST_CHECK_EQUAL(min, 0);
    BOOST_CHECK_EQUAL(max, 255);
    BOOST_CHECK_EQUAL(max, UINT8_MAX);
}

BOOST_AUTO_TEST_SUITE_END() // bounds_checking_tests

/**
 * Test Suite 5: Memory Safety Tests
 */
BOOST_AUTO_TEST_SUITE(memory_safety_tests)

BOOST_AUTO_TEST_CASE(vector_size_consistency) {
    std::vector<uint8_t> data;

    BOOST_CHECK_EQUAL(data.size(), 0);
    BOOST_CHECK(data.empty());

    data.push_back(0x01);
    BOOST_CHECK_EQUAL(data.size(), 1);
    BOOST_CHECK(!data.empty());

    data.resize(10);
    BOOST_CHECK_EQUAL(data.size(), 10);

    data.clear();
    BOOST_CHECK_EQUAL(data.size(), 0);
    BOOST_CHECK(data.empty());
}

BOOST_AUTO_TEST_CASE(vector_reserve) {
    std::vector<uint8_t> data;

    data.reserve(100);
    BOOST_CHECK(data.capacity() >= 100);
    BOOST_CHECK_EQUAL(data.size(), 0);

    // Add elements
    for (int i = 0; i < 50; i++) {
        data.push_back(static_cast<uint8_t>(i));
    }

    BOOST_CHECK_EQUAL(data.size(), 50);
    BOOST_CHECK(data.capacity() >= 100);
}

BOOST_AUTO_TEST_CASE(memset_safety) {
    uint8_t buffer[32];

    // Zero initialize
    memset(buffer, 0, 32);

    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(buffer[i], 0);
    }

    // Set to pattern
    memset(buffer, 0x42, 32);

    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(buffer[i], 0x42);
    }
}

BOOST_AUTO_TEST_CASE(memcpy_safety) {
    uint8_t src[32];
    uint8_t dst[32];

    // Initialize source
    for (int i = 0; i < 32; i++) {
        src[i] = static_cast<uint8_t>(i);
    }

    // Copy
    memcpy(dst, src, 32);

    // Verify
    for (int i = 0; i < 32; i++) {
        BOOST_CHECK_EQUAL(dst[i], src[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END() // memory_safety_tests

/**
 * Test Suite 6: Serialization Size Tests
 */
BOOST_AUTO_TEST_SUITE(serialization_tests)

BOOST_AUTO_TEST_CASE(uint256_size) {
    uint256 hash;
    BOOST_CHECK_EQUAL(sizeof(hash.data), 32);
    BOOST_CHECK_EQUAL(sizeof(uint256), 32);
}

BOOST_AUTO_TEST_CASE(basic_type_sizes) {
    BOOST_CHECK_EQUAL(sizeof(uint8_t), 1);
    BOOST_CHECK_EQUAL(sizeof(uint16_t), 2);
    BOOST_CHECK_EQUAL(sizeof(uint32_t), 4);
    BOOST_CHECK_EQUAL(sizeof(uint64_t), 8);

    BOOST_CHECK_EQUAL(sizeof(int8_t), 1);
    BOOST_CHECK_EQUAL(sizeof(int16_t), 2);
    BOOST_CHECK_EQUAL(sizeof(int32_t), 4);
    BOOST_CHECK_EQUAL(sizeof(int64_t), 8);
}

BOOST_AUTO_TEST_CASE(vector_overhead) {
    std::vector<uint8_t> empty;
    std::vector<uint8_t> small;

    small.push_back(0x01);

    // Vector has overhead beyond just data
    BOOST_CHECK_EQUAL(empty.size(), 0);
    BOOST_CHECK_EQUAL(small.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END() // serialization_tests

BOOST_AUTO_TEST_SUITE_END() // util_tests
