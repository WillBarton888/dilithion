// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.1a — Lifecycle tests for port-CPeerManager.
//
// Per active_contract.md "Acceptance criteria" + decomposition §"PR6.5b.1a",
// these 4 tests focus on the port-CPeerManager surface that the new
// `--usenewpeerman=1` flag exposes:
//   1. test_port_cpeermanager_polymorphic_as_isynccoordinator
//      — port-CPeerManager IS-A ISyncCoordinator; `unique_ptr<ISyncCoordinator>`
//        can hold a CPeerManager (the runtime-selection pattern in
//        dilithion-node.cpp / dilv-node.cpp main()).
//   2. test_vacuous_defaults_explicit
//      — IsInitialBlockDownload()=true, IsSynced()=false, GetHeadersSyncPeer()=-1
//        match the documented skeleton stubs (PR6.5b.5/6 will replace with
//        real bodies; until then, conservative defaults mean a node
//        accidentally booted with flag=1 won't relay — safest fallback).
//   3. test_lifecycle_idempotency_connect
//      — OnPeerConnected(NodeId) is idempotent; calling twice for the same
//        NodeId leaves m_peers stable; OnPeerDisconnected for an unknown
//        NodeId is a no-op.
//   4. test_lifecycle_observable_state_after_ops
//      — vacuous defaults remain unchanged across lifecycle hook calls;
//        ISyncCoordinator query results are stable while peer count fluctuates.
//
// Out of unit-test scope (covered by diff subagent review + manual smoke):
//   - flag parsing (Config struct is in node-binary translation unit only)
//   - runtime selection logic in main() (integration-test territory)
//   - legacy CIbdCoordinator path (unchanged by 1a; heavy fixture per
//     ibd_coordinator_tests.cpp would be redundant overhead here)
//
// Pattern: void test_*() + custom main(), matching the existing 39 tests.
// No Boost framework.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <net/connman.h>
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>
#include <net/port/sync_coordinator.h>

#include <primitives/block.h>

#include <cassert>
#include <iostream>
#include <memory>

namespace {

// Shared fixture builder. Returns a constructed port-CPeerManager owning
// all 5 refs through static-storage members so callers can use it as
// `ISyncCoordinator*` or `CPeerManager*` interchangeably.
struct LifecycleFixture {
    static const ::Dilithion::ChainParams chainparams;
    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    CConnman connman;
    dilithion::net::port::CConnmanAdapter connman_adapter;
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer scorer;
    dilithion::net::port::CPeerManager pm;

    LifecycleFixture()
        : chain_selector(chainstate),
          connman_adapter(connman),
          pm(connman_adapter, addrman, scorer, chain_selector, chainparams)
    {}
};

const ::Dilithion::ChainParams LifecycleFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

}  // anonymous namespace

// ============================================================================
// Test 1 — port-CPeerManager IS-A ISyncCoordinator (polymorphic via base ptr).
// This is the runtime pattern used by dilithion-node.cpp / dilv-node.cpp
// main() at PR6.5b.1a's conditional construction site.
// ============================================================================
void test_port_cpeermanager_polymorphic_as_isynccoordinator()
{
    std::cout << "  test_port_cpeermanager_polymorphic_as_isynccoordinator..." << std::flush;

    LifecycleFixture fix;

    // Mirror the runtime pattern: store as ISyncCoordinator* (the type held
    // by g_node_context.sync_coordinator). The pointer assignment must
    // succeed because CPeerManager : public ISyncCoordinator.
    dilithion::net::port::ISyncCoordinator* sc = &fix.pm;
    assert(sc != nullptr);

    // Polymorphic dispatch through the base class works.
    assert(sc->IsInitialBlockDownload() == true);
    assert(sc->IsSynced() == false);
    assert(sc->GetHeadersSyncPeer() == -1);

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — explicit vacuous-default contract per peer_manager.cpp:46-60.
// PR6.5b.1a relies on these defaults: a node accidentally booted with flag=1
// before PR6.5b.5/6 ships real bodies will not relay because IsIBD=true.
// ============================================================================
void test_vacuous_defaults_explicit()
{
    std::cout << "  test_vacuous_defaults_explicit..." << std::flush;

    LifecycleFixture fix;

    // Documented safe defaults per peer_manager.cpp comments.
    assert(fix.pm.IsInitialBlockDownload() == true);   // "in IBD; behave conservatively"
    assert(fix.pm.IsSynced() == false);                // "not synced"
    assert(fix.pm.GetHeadersSyncPeer() == -1);         // "no sync peer selected"
    assert(fix.pm.GetPeerCount() == 0);                // "fresh — no peers connected"

    // GetPeerInfo() returns empty vector when no peers connected.
    auto peers = fix.pm.GetPeerInfo();
    assert(peers.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — lifecycle idempotency on OnPeerConnected/OnPeerDisconnected.
// Skeleton bodies (peer_manager.cpp:111-120) implement these; verify they
// behave correctly under repeated / unexpected calls.
// ============================================================================
void test_lifecycle_idempotency_connect()
{
    std::cout << "  test_lifecycle_idempotency_connect..." << std::flush;

    LifecycleFixture fix;

    // Initial state: empty peer set.
    assert(fix.pm.GetPeerCount() == 0);

    // OnPeerConnected idempotency: same NodeId twice → m_peers size stable at 1.
    fix.pm.OnPeerConnected(42);
    assert(fix.pm.GetPeerCount() == 1);
    fix.pm.OnPeerConnected(42);  // duplicate
    assert(fix.pm.GetPeerCount() == 1);

    // Add a different peer.
    fix.pm.OnPeerConnected(7);
    assert(fix.pm.GetPeerCount() == 2);

    // OnPeerDisconnected on unknown NodeId: no-op, no crash.
    fix.pm.OnPeerDisconnected(99);
    assert(fix.pm.GetPeerCount() == 2);

    // Disconnect known NodeId: count drops.
    fix.pm.OnPeerDisconnected(42);
    assert(fix.pm.GetPeerCount() == 1);

    // Disconnect remaining.
    fix.pm.OnPeerDisconnected(7);
    assert(fix.pm.GetPeerCount() == 0);

    // Disconnect now-unknown NodeId again: still no-op.
    fix.pm.OnPeerDisconnected(42);
    assert(fix.pm.GetPeerCount() == 0);

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — vacuous-default ISyncCoordinator answers are stable across
// lifecycle hook calls. PR6.5b.5/6 will introduce real semantics; this test
// locks the current behavior (peer count fluctuates while ISyncCoordinator
// query results stay at safe defaults).
// ============================================================================
void test_lifecycle_observable_state_after_ops()
{
    std::cout << "  test_lifecycle_observable_state_after_ops..." << std::flush;

    LifecycleFixture fix;

    auto check_vacuous = [&]() {
        assert(fix.pm.IsInitialBlockDownload() == true);
        assert(fix.pm.IsSynced() == false);
        assert(fix.pm.GetHeadersSyncPeer() == -1);
    };

    check_vacuous();  // initial

    fix.pm.OnPeerConnected(1);
    fix.pm.OnPeerConnected(2);
    fix.pm.OnPeerConnected(3);
    assert(fix.pm.GetPeerCount() == 3);
    check_vacuous();  // ISyncCoordinator answers unchanged after connects

    fix.pm.OnOrphanBlockReceived();  // skeleton no-op
    fix.pm.OnBlockConnected();       // skeleton no-op
    fix.pm.Tick();                   // skeleton no-op
    check_vacuous();                 // unchanged after no-op hooks

    fix.pm.OnPeerDisconnected(1);
    fix.pm.OnPeerDisconnected(2);
    fix.pm.OnPeerDisconnected(3);
    assert(fix.pm.GetPeerCount() == 0);
    check_vacuous();                 // unchanged after disconnects

    std::cout << " OK\n";
}

// ============================================================================
// Test 5 — v4.3.3: headers path mirrors best-known height into port download
// state (regression for IBD stall when inbound headers bypass HandleHeaders).
// ============================================================================
void test_notify_peer_best_known_from_headers_updates_port_height()
{
    std::cout << "  test_notify_peer_best_known_from_headers_updates_port_height..."
              << std::flush;

    LifecycleFixture fix;
    constexpr int kPeer = 51;
    fix.pm.OnPeerConnected(kPeer);
    assert(fix.pm.GetPeerBestKnownBlockHeight(kPeer) == -1);

    uint256 dummy;
    dummy.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    fix.pm.NotifyPeerBestKnownFromHeaders(kPeer, 44812, dummy);
    assert(fix.pm.GetPeerBestKnownBlockHeight(kPeer) == 44812);

    fix.pm.NotifyPeerBestKnownFromHeaders(kPeer, 44800, dummy);  // regression down
    assert(fix.pm.GetPeerBestKnownBlockHeight(kPeer) == 44812);

    fix.pm.NotifyPeerBestKnownFromHeaders(kPeer, 44906, dummy);
    assert(fix.pm.GetPeerBestKnownBlockHeight(kPeer) == 44906);

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.1a — Lifecycle tests for port-CPeerManager\n";
    std::cout << "  (5-test suite per active_contract.md + v4.3.3 catch-up)\n\n";

    try {
        test_port_cpeermanager_polymorphic_as_isynccoordinator();
        test_vacuous_defaults_explicit();
        test_lifecycle_idempotency_connect();
        test_lifecycle_observable_state_after_ops();
        test_notify_peer_best_known_from_headers_updates_port_height();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 5 PR6.5b.1a lifecycle tests passed.\n";
    return 0;
}
