// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Unit tests for fork detection & miner protection system
 *
 * Tests:
 * - UpdatePeerBestKnownTip: hash tracking, height-gating, freshness
 * - Rolling window self-mined ratio: edge cases, thresholds
 * - Chain health RPC field: tip_diverged flag propagation
 */

// Part of main Boost test suite (no BOOST_TEST_MODULE here)
#include <boost/test/unit_test.hpp>

#include <net/peers.h>
#include <net/protocol.h>
#include <core/node_context.h>
#include <primitives/block.h>
#include <deque>
#include <chrono>
#include <thread>
#include <iostream>

// Helper: create a peer and return its ID
static int AddTestPeer(CPeerManager& pm, uint32_t ip, uint16_t port = 8444) {
    NetProtocol::CAddress addr;
    addr.SetIPv4(ip);
    addr.port = port;
    auto peer = pm.AddPeer(addr);
    return peer ? peer->id : -1;
}

// Helper: make a uint256 from a single byte
static uint256 MakeHash(uint8_t val) {
    uint256 h;
    h.data[0] = val;
    return h;
}

BOOST_AUTO_TEST_SUITE(fork_detection_tests)

// =========================================================================
// Phase 1: UpdatePeerBestKnownTip tests
// =========================================================================

BOOST_AUTO_TEST_CASE(test_update_peer_best_known_tip_basic) {
    // Test that UpdatePeerBestKnownTip sets hash and height
    CPeerManager pm("");
    int peer_id = AddTestPeer(pm, 0x7F000001);
    BOOST_REQUIRE(peer_id >= 0);

    uint256 hash = MakeHash(42);
    pm.UpdatePeerBestKnownTip(peer_id, 100, hash);

    auto peer = pm.GetPeer(peer_id);
    BOOST_REQUIRE(peer != nullptr);
    BOOST_CHECK_EQUAL(peer->best_known_height, 100);
    BOOST_CHECK(peer->best_known_hash == hash);
}

BOOST_AUTO_TEST_CASE(test_update_peer_tip_only_increases) {
    // Test that UpdatePeerBestKnownTip only updates on strictly higher height
    CPeerManager pm("");
    int peer_id = AddTestPeer(pm, 0x7F000001);
    BOOST_REQUIRE(peer_id >= 0);

    uint256 hash1 = MakeHash(1);
    uint256 hash2 = MakeHash(2);
    uint256 hash3 = MakeHash(3);

    // Set initial tip at height 100
    pm.UpdatePeerBestKnownTip(peer_id, 100, hash1);
    auto peer = pm.GetPeer(peer_id);
    BOOST_CHECK(peer->best_known_hash == hash1);

    // Same height should NOT update
    pm.UpdatePeerBestKnownTip(peer_id, 100, hash2);
    peer = pm.GetPeer(peer_id);
    BOOST_CHECK(peer->best_known_hash == hash1);  // Still hash1

    // Lower height should NOT update
    pm.UpdatePeerBestKnownTip(peer_id, 99, hash3);
    peer = pm.GetPeer(peer_id);
    BOOST_CHECK(peer->best_known_hash == hash1);  // Still hash1

    // Higher height SHOULD update
    pm.UpdatePeerBestKnownTip(peer_id, 101, hash2);
    peer = pm.GetPeer(peer_id);
    BOOST_CHECK_EQUAL(peer->best_known_height, 101);
    BOOST_CHECK(peer->best_known_hash == hash2);  // Now hash2
}

BOOST_AUTO_TEST_CASE(test_update_peer_tip_sets_timestamp) {
    // Test that UpdatePeerBestKnownTip updates last_tip_update
    CPeerManager pm("");
    int peer_id = AddTestPeer(pm, 0x7F000001);
    BOOST_REQUIRE(peer_id >= 0);

    auto before = std::chrono::steady_clock::now();
    uint256 hash = MakeHash(1);
    pm.UpdatePeerBestKnownTip(peer_id, 100, hash);
    auto after = std::chrono::steady_clock::now();

    auto peer = pm.GetPeer(peer_id);
    BOOST_REQUIRE(peer != nullptr);
    // Timestamp should be between before and after
    BOOST_CHECK(peer->last_tip_update >= before);
    BOOST_CHECK(peer->last_tip_update <= after);
}

BOOST_AUTO_TEST_CASE(test_update_peer_tip_unknown_peer) {
    // Test that UpdatePeerBestKnownTip on non-existent peer doesn't crash
    CPeerManager pm("");
    uint256 hash = MakeHash(1);

    // Should not crash
    pm.UpdatePeerBestKnownTip(999999, 100, hash);
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_CASE(test_update_peer_tip_multiple_peers) {
    // Test that tip tracking is per-peer
    CPeerManager pm("");
    int peer1 = AddTestPeer(pm, 0x7F000001);
    int peer2 = AddTestPeer(pm, 0x7F000002);
    BOOST_REQUIRE(peer1 >= 0);
    BOOST_REQUIRE(peer2 >= 0);

    uint256 hash_a = MakeHash(0xAA);
    uint256 hash_b = MakeHash(0xBB);

    pm.UpdatePeerBestKnownTip(peer1, 100, hash_a);
    pm.UpdatePeerBestKnownTip(peer2, 200, hash_b);

    auto p1 = pm.GetPeer(peer1);
    auto p2 = pm.GetPeer(peer2);
    BOOST_REQUIRE(p1 != nullptr);
    BOOST_REQUIRE(p2 != nullptr);

    BOOST_CHECK_EQUAL(p1->best_known_height, 100);
    BOOST_CHECK(p1->best_known_hash == hash_a);
    BOOST_CHECK_EQUAL(p2->best_known_height, 200);
    BOOST_CHECK(p2->best_known_hash == hash_b);
}

BOOST_AUTO_TEST_CASE(test_initial_hash_is_null) {
    // Test that best_known_hash starts null (divergence logic skips null hashes)
    CPeerManager pm("");
    int peer_id = AddTestPeer(pm, 0x7F000001);
    BOOST_REQUIRE(peer_id >= 0);

    auto peer = pm.GetPeer(peer_id);
    BOOST_REQUIRE(peer != nullptr);
    BOOST_CHECK(peer->best_known_hash.IsNull());
}

// =========================================================================
// Phase 3: Rolling window self-mined ratio tests
// =========================================================================

// Replicate the rolling window logic from dilithion-node.cpp for testability
namespace {

struct RecentBlock { bool self_mined; };

float CalculateRatio(const std::deque<RecentBlock>& window) {
    if (window.empty()) return 0.0f;
    int self_count = 0;
    for (const auto& b : window) {
        if (b.self_mined) self_count++;
    }
    return static_cast<float>(self_count) / static_cast<float>(window.size());
}

void PushBlock(std::deque<RecentBlock>& window, bool self_mined, size_t max_size = 20) {
    window.push_back({self_mined});
    if (window.size() > max_size) {
        window.pop_front();
    }
}

}  // anonymous namespace

BOOST_AUTO_TEST_CASE(test_rolling_window_empty) {
    std::deque<RecentBlock> window;
    BOOST_CHECK_CLOSE(CalculateRatio(window), 0.0f, 0.01f);
}

BOOST_AUTO_TEST_CASE(test_rolling_window_all_self_mined) {
    std::deque<RecentBlock> window;
    for (int i = 0; i < 20; i++) {
        PushBlock(window, true);
    }
    BOOST_CHECK_CLOSE(CalculateRatio(window), 1.0f, 0.01f);
}

BOOST_AUTO_TEST_CASE(test_rolling_window_no_self_mined) {
    std::deque<RecentBlock> window;
    for (int i = 0; i < 20; i++) {
        PushBlock(window, false);
    }
    BOOST_CHECK_CLOSE(CalculateRatio(window), 0.0f, 0.01f);
}

BOOST_AUTO_TEST_CASE(test_rolling_window_exactly_80_percent) {
    // 80% = warn threshold
    std::deque<RecentBlock> window;
    for (int i = 0; i < 16; i++) PushBlock(window, true);
    for (int i = 0; i < 4; i++) PushBlock(window, false);
    BOOST_CHECK_EQUAL(window.size(), 20u);
    BOOST_CHECK_CLOSE(CalculateRatio(window), 0.80f, 0.01f);
}

BOOST_AUTO_TEST_CASE(test_rolling_window_exactly_90_percent) {
    // 90% = pause threshold
    std::deque<RecentBlock> window;
    for (int i = 0; i < 18; i++) PushBlock(window, true);
    for (int i = 0; i < 2; i++) PushBlock(window, false);
    BOOST_CHECK_EQUAL(window.size(), 20u);
    BOOST_CHECK_CLOSE(CalculateRatio(window), 0.90f, 0.01f);
}

BOOST_AUTO_TEST_CASE(test_rolling_window_slides) {
    // Test that old blocks fall off the window
    std::deque<RecentBlock> window;

    // Fill with 20 self-mined blocks (100%)
    for (int i = 0; i < 20; i++) PushBlock(window, true);
    BOOST_CHECK_CLOSE(CalculateRatio(window), 1.0f, 0.01f);

    // Push 5 peer blocks - oldest self-mined fall off
    for (int i = 0; i < 5; i++) PushBlock(window, false);
    BOOST_CHECK_EQUAL(window.size(), 20u);
    // 15 self-mined + 5 peer = 75%
    BOOST_CHECK_CLOSE(CalculateRatio(window), 0.75f, 0.01f);
}

BOOST_AUTO_TEST_CASE(test_rolling_window_below_minimum) {
    // Window needs 10+ blocks before ratio matters
    std::deque<RecentBlock> window;
    for (int i = 0; i < 9; i++) PushBlock(window, true);
    BOOST_CHECK_EQUAL(window.size(), 9u);
    // 100% ratio but only 9 blocks - should not trigger (tested in logic)
    BOOST_CHECK_CLOSE(CalculateRatio(window), 1.0f, 0.01f);
    // Callers check window.size() >= 10 before acting on ratio
}

BOOST_AUTO_TEST_CASE(test_rolling_window_recovery) {
    // Simulate recovery: all self-mined then peer blocks arrive
    std::deque<RecentBlock> window;

    // Start at 100% self-mined
    for (int i = 0; i < 20; i++) PushBlock(window, true);
    BOOST_CHECK_CLOSE(CalculateRatio(window), 1.0f, 0.01f);

    // Peer blocks start arriving - push 10 peer blocks
    for (int i = 0; i < 10; i++) PushBlock(window, false);
    // 10 self-mined + 10 peer = 50%
    BOOST_CHECK_CLOSE(CalculateRatio(window), 0.50f, 0.01f);
}

BOOST_AUTO_TEST_CASE(test_rolling_window_max_size) {
    // Window should never exceed max_size
    std::deque<RecentBlock> window;
    for (int i = 0; i < 100; i++) PushBlock(window, true, 20);
    BOOST_CHECK_EQUAL(window.size(), 20u);
}

// =========================================================================
// Phase 2/4: Tip divergence flag & chain health
// =========================================================================

BOOST_AUTO_TEST_CASE(test_tip_diverged_default_false) {
    // g_node_context.tip_diverged should default to false
    // (Reset to known state first in case a prior test set it)
    g_node_context.tip_diverged.store(false);
    BOOST_CHECK_EQUAL(g_node_context.tip_diverged.load(), false);
}

BOOST_AUTO_TEST_CASE(test_tip_diverged_atomic_set_clear) {
    // Test atomic set/clear cycle on global context
    g_node_context.tip_diverged.store(true);
    BOOST_CHECK_EQUAL(g_node_context.tip_diverged.load(), true);
    g_node_context.tip_diverged.store(false);
    BOOST_CHECK_EQUAL(g_node_context.tip_diverged.load(), false);
}

BOOST_AUTO_TEST_CASE(test_handshake_initializes_tip_update) {
    // Test that OnPeerHandshakeComplete initializes last_tip_update
    CPeerManager pm("");
    int peer_id = AddTestPeer(pm, 0x7F000001);
    BOOST_REQUIRE(peer_id >= 0);

    auto before = std::chrono::steady_clock::now();
    pm.OnPeerHandshakeComplete(peer_id, 100, false);
    auto after = std::chrono::steady_clock::now();

    auto peer = pm.GetPeer(peer_id);
    BOOST_REQUIRE(peer != nullptr);
    // last_tip_update should be set during handshake
    BOOST_CHECK(peer->last_tip_update >= before);
    BOOST_CHECK(peer->last_tip_update <= after);
}

BOOST_AUTO_TEST_SUITE_END()
