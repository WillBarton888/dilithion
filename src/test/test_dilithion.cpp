// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Main test entry point for Dilithion Test Suite
 *
 * This file initializes the Boost Unit Test Framework for all Dilithion tests.
 * Following Bitcoin Core's testing approach.
 */

#define BOOST_TEST_MODULE Dilithion Test Suite
#include <boost/test/included/unit_test.hpp>

#include <iostream>
#include <cstring>

// RandomX initialization
extern "C" void randomx_init_cache(const void* key, size_t key_len);

/**
 * Global test suite setup
 */
struct DilithionTestSetup {
    DilithionTestSetup() {
        std::cout << "Dilithion Test Suite Starting..." << std::endl;
        std::cout << "Using Boost.Test version "
                  << BOOST_VERSION / 100000 << "."
                  << BOOST_VERSION / 100 % 1000 << "."
                  << BOOST_VERSION % 100 << std::endl;

        // Initialize RandomX for tests that need GetHash()
        // Note: Some CI environments may have limited memory
        try {
            const char* rx_key = "Dilithion-RandomX-Test";
            randomx_init_cache(rx_key, strlen(rx_key));
            std::cout << "RandomX initialized for testing" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "Warning: RandomX init failed (" << e.what() << ") - tests requiring GetHash() will be skipped" << std::endl;
        }
    }

    ~DilithionTestSetup() {
        std::cout << "Dilithion Test Suite Complete" << std::endl;
    }
};

BOOST_GLOBAL_FIXTURE(DilithionTestSetup);

/**
 * Basic sanity check test
 */
BOOST_AUTO_TEST_SUITE(sanity_tests)

BOOST_AUTO_TEST_CASE(basic_sanity) {
    BOOST_CHECK_EQUAL(1 + 1, 2);
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()
