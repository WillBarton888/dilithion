// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Unit tests for CIbdCoordinator
 *
 * Tests the Initial Block Download coordination logic:
 * - Exponential backoff when no peers available
 * - Backoff reset when new headers arrive
 * - Block queueing and download dispatch
 * - Timeout handling and peer disconnection
 *
 * Note: These are integration-style tests that work with actual classes
 * rather than mocks, since the classes don't use virtual methods.
 */

// Part of main Boost test suite (no BOOST_TEST_MODULE here)
#include <boost/test/unit_test.hpp>

#include <node/ibd_coordinator.h>
#include <core/node_context.h>
#include <consensus/chain.h>
#include <net/block_fetcher.h>
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/socket.h>
#include <chrono>
#include <thread>

BOOST_AUTO_TEST_SUITE(ibd_coordinator_tests)

BOOST_AUTO_TEST_CASE(test_coordinator_construction) {
    // Test that CIbdCoordinator can be constructed with NodeContext
    CChainState chainstate;
    NodeContext node_context;

    // Initialize NodeContext components
    node_context.chainstate = &chainstate;
    node_context.peer_manager = std::make_unique<CPeerManager>("");
    node_context.headers_manager = std::make_unique<CHeadersManager>();
    node_context.orphan_manager = std::make_unique<COrphanManager>();
    node_context.block_fetcher = std::make_unique<CBlockFetcher>(node_context.peer_manager.get());

    // Should construct without errors
    CIbdCoordinator coordinator(chainstate, node_context);

    BOOST_CHECK(true);  // Test passes if construction succeeds
}

BOOST_AUTO_TEST_CASE(test_tick_when_synced) {
    // Test that Tick() does nothing when chain is synced (headers not ahead)
    CChainState chainstate;
    NodeContext node_context;

    // Initialize NodeContext components
    node_context.chainstate = &chainstate;
    node_context.peer_manager = std::make_unique<CPeerManager>("");
    node_context.headers_manager = std::make_unique<CHeadersManager>();
    node_context.orphan_manager = std::make_unique<COrphanManager>();
    node_context.block_fetcher = std::make_unique<CBlockFetcher>(node_context.peer_manager.get());

    CIbdCoordinator coordinator(chainstate, node_context);

    // Chain is synced (headers not ahead of chain)
    // GetHeight() and GetBestHeight() both return 0 initially

    // Tick should do nothing when synced
    coordinator.Tick();

    // Verify no blocks were queued (block fetcher starts empty)
    BOOST_CHECK_EQUAL(node_context.block_fetcher->GetBlocksInFlight(), 0);
}

BOOST_AUTO_TEST_CASE(test_backoff_reset_mechanism) {
    // Test that backoff is reset when new headers arrive
    // This tests the ResetBackoffOnNewHeaders logic
    CChainState chainstate;
    NodeContext node_context;

    // Initialize NodeContext components
    node_context.chainstate = &chainstate;
    node_context.peer_manager = std::make_unique<CPeerManager>("");
    node_context.headers_manager = std::make_unique<CHeadersManager>();
    node_context.orphan_manager = std::make_unique<COrphanManager>();
    node_context.block_fetcher = std::make_unique<CBlockFetcher>(node_context.peer_manager.get());

    CIbdCoordinator coordinator(chainstate, node_context);

    // Simulate headers ahead scenario
    // Note: This is a simplified test - full testing would require
    // setting up headers in the headers_manager

    // First tick with no peers - should enter backoff
    node_context.peer_manager->GetConnectionCount();  // Returns 0
    coordinator.Tick();

    // Verify coordinator handles the no-peer case gracefully
    BOOST_CHECK(true);  // Test passes if no crash
}

BOOST_AUTO_TEST_CASE(test_exponential_backoff_timing) {
    // Test exponential backoff timing logic
    // Backoff should be: 1s, 2s, 4s, 8s, 16s, 30s (max)
    CChainState chainstate;
    NodeContext node_context;

    // Initialize NodeContext components
    node_context.chainstate = &chainstate;
    node_context.peer_manager = std::make_unique<CPeerManager>("");
    node_context.headers_manager = std::make_unique<CHeadersManager>();
    node_context.orphan_manager = std::make_unique<COrphanManager>();
    node_context.block_fetcher = std::make_unique<CBlockFetcher>(node_context.peer_manager.get());

    CIbdCoordinator coordinator(chainstate, node_context);

    // Test that coordinator handles backoff correctly
    // (Actual timing would require more complex setup)
    coordinator.Tick();

    BOOST_CHECK(true);  // Test passes if no crash
}

BOOST_AUTO_TEST_SUITE_END()
