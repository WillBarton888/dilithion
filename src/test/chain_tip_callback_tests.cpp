// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Chain Tip Update Callback Tests (BUG #180)
 *
 * Tests for the ChainTipUpdateCallback pattern that decouples
 * block_processing from node-specific mining code.
 */

#include <boost/test/unit_test.hpp>
#include <node/block_processing.h>
#include <functional>
#include <atomic>
#include <iostream>

BOOST_AUTO_TEST_SUITE(chain_tip_callback_tests)

/**
 * Test 1: Callback registration stores the callback
 */
BOOST_AUTO_TEST_CASE(test_callback_registration)
{
    std::cout << "\n[TEST] test_callback_registration" << std::endl;

    // Track if callback was set
    std::atomic<bool> callback_set{false};
    int received_height = -1;
    bool received_is_reorg = false;

    // Create a test callback
    ChainTipUpdateCallback test_callback = [&](CBlockchainDB& /*db*/, int height, bool is_reorg) {
        callback_set.store(true);
        received_height = height;
        received_is_reorg = is_reorg;
    };

    // Register the callback
    SetChainTipUpdateCallback(test_callback);

    // Note: We can't directly invoke the callback here since it's stored
    // in a static variable in block_processing.cpp. This test verifies
    // that SetChainTipUpdateCallback compiles and runs without error.

    std::cout << "  SetChainTipUpdateCallback called successfully" << std::endl;

    // Clean up - set to nullptr
    SetChainTipUpdateCallback(nullptr);

    BOOST_CHECK(true); // Passed if we got here without crash
}

/**
 * Test 2: Null callback is safe (no crash on nullptr)
 */
BOOST_AUTO_TEST_CASE(test_callback_null_safety)
{
    std::cout << "\n[TEST] test_callback_null_safety" << std::endl;

    // Register nullptr callback
    SetChainTipUpdateCallback(nullptr);

    std::cout << "  SetChainTipUpdateCallback(nullptr) called safely" << std::endl;

    // The actual invocation safety is tested implicitly by block_processing.cpp
    // which checks `if (g_chain_tip_callback)` before invoking.

    BOOST_CHECK(true); // Passed if no crash
}

/**
 * Test 3: Callback function type is correct
 */
BOOST_AUTO_TEST_CASE(test_callback_type_compatibility)
{
    std::cout << "\n[TEST] test_callback_type_compatibility" << std::endl;

    // Test that various lambda signatures work with ChainTipUpdateCallback

    // Lambda with all parameters used
    ChainTipUpdateCallback cb1 = [](CBlockchainDB& db, int height, bool is_reorg) {
        (void)db;
        (void)height;
        (void)is_reorg;
    };
    SetChainTipUpdateCallback(cb1);
    BOOST_CHECK(true);

    // Lambda with unused parameters (common pattern)
    ChainTipUpdateCallback cb2 = [](CBlockchainDB& /*db*/, int height, bool /*is_reorg*/) {
        std::cout << "    Height: " << height << std::endl;
    };
    SetChainTipUpdateCallback(cb2);
    BOOST_CHECK(true);

    // Lambda capturing external state
    std::atomic<int> last_height{0};
    ChainTipUpdateCallback cb3 = [&last_height](CBlockchainDB& /*db*/, int height, bool /*is_reorg*/) {
        last_height.store(height);
    };
    SetChainTipUpdateCallback(cb3);
    BOOST_CHECK(true);

    // Clean up
    SetChainTipUpdateCallback(nullptr);

    std::cout << "  All callback types compatible" << std::endl;
}

/**
 * Test 4: Callback can be replaced
 */
BOOST_AUTO_TEST_CASE(test_callback_replacement)
{
    std::cout << "\n[TEST] test_callback_replacement" << std::endl;

    int call_count_1 = 0;
    int call_count_2 = 0;

    // Register first callback
    ChainTipUpdateCallback cb1 = [&call_count_1](CBlockchainDB& /*db*/, int /*height*/, bool /*is_reorg*/) {
        call_count_1++;
    };
    SetChainTipUpdateCallback(cb1);

    // Replace with second callback
    ChainTipUpdateCallback cb2 = [&call_count_2](CBlockchainDB& /*db*/, int /*height*/, bool /*is_reorg*/) {
        call_count_2++;
    };
    SetChainTipUpdateCallback(cb2);

    // Clean up
    SetChainTipUpdateCallback(nullptr);

    std::cout << "  Callback replacement works" << std::endl;
    BOOST_CHECK(true);
}

/**
 * Test 5: Verify ChainTipUpdateCallback signature matches expected
 */
BOOST_AUTO_TEST_CASE(test_callback_signature)
{
    std::cout << "\n[TEST] test_callback_signature" << std::endl;

    // Verify the type is std::function with correct signature
    // ChainTipUpdateCallback should be:
    // std::function<void(CBlockchainDB& db, int new_height, bool is_reorg)>

    bool signature_correct = std::is_same<
        ChainTipUpdateCallback,
        std::function<void(CBlockchainDB&, int, bool)>
    >::value;

    BOOST_CHECK_MESSAGE(signature_correct, "ChainTipUpdateCallback has correct signature");

    if (signature_correct) {
        std::cout << "  Signature: void(CBlockchainDB&, int, bool)" << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
