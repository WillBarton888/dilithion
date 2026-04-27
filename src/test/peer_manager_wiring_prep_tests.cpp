// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.0 — Wiring prep tests.
//
// Per active_contract.md / decomposition §"PR6.5b.0", these tests verify
// the new infrastructure makes port-CPeerManager constructible:
//   1. CAddrMan_v2 default-constructs (production IAddressManager impl)
//   2. CPeerScorer default-constructs (port IPeerScorer impl)
//   3. CConnmanAdapter wraps a CConnman cleanly (option-(b) IConnectionManager
//      strategy locked per subagent V5 ground-truth review — 7 of 8 virtuals
//      diverge from CConnman's surface, so adapter is mandatory)
//   4. port-CPeerManager constructible with all 5 refs (connman via adapter,
//      addrman, peer_scorer, chain_selector, chainparams) — the PR6.5b.0 goal:
//      construction-ready under flag=1 path.
//
// Pattern matches src/test/chain_selector_tests.cpp + headers_manager_to_
// chain_selector_wiring_tests.cpp: void test_*() functions + custom main().
// No Boost framework.
//
// Shutdown ordering: implicit. Test 4 constructs all 5 refs as local
// unique_ptrs + a local CPeerManager. Going out of scope at function end
// destructs in reverse order: CPeerManager (last-in, first-out) → adapter →
// peer_scorer → addrman → connman → chainstate. If any non-owning ref
// outlives its target, a use-after-free would surface as a crash here.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <net/connman.h>
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>

#include <cassert>
#include <iostream>
#include <memory>

// ============================================================================
// Test 1 — CAddrMan_v2 default-constructs without throwing.
// PR6.5b.0 ships this as the production IAddressManager instance in NodeContext.
// ============================================================================
void test_addrman_construction()
{
    std::cout << "  test_addrman_construction..." << std::flush;

    auto addrman = std::make_unique<dilithion::net::port::CAddrMan_v2>();
    assert(addrman);
    assert(addrman->Size() == 0);  // Fresh instance has no entries

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — CPeerScorer default-constructs without throwing.
// PR6.5b.0 ships this as the production IPeerScorer instance in NodeContext.
// ============================================================================
void test_peer_scorer_construction()
{
    std::cout << "  test_peer_scorer_construction..." << std::flush;

    auto scorer = std::make_unique<dilithion::net::port::CPeerScorer>();
    assert(scorer);
    assert(scorer->GetScoreMapSizeForTest() == 0);  // No tracked nodes yet

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — CConnmanAdapter wraps a CConnman cleanly.
// Verifies option-(b) strategy: 8 IConnectionManager virtuals all callable
// over a real CConnman through the adapter.
// ============================================================================
void test_connman_adapter_construction()
{
    std::cout << "  test_connman_adapter_construction..." << std::flush;

    auto connman = std::make_unique<CConnman>();
    auto adapter = std::make_unique<dilithion::net::port::CConnmanAdapter>(*connman);
    assert(adapter);

    // Trivial real methods (count walks over empty node list).
    assert(adapter->GetTotalInbound() == 0);
    assert(adapter->GetTotalOutbound() == 0);
    assert(adapter->GetConnectionCount(dilithion::net::OutboundClass::FullRelay) == 0);

    // Stub methods return safe defaults (TODO markers in adapter for PR6.5b.5/6).
    assert(!adapter->IsBanned("203.0.113.1"));
    assert(adapter->ConnectNode("203.0.113.1:8444",
                                dilithion::net::OutboundClass::FullRelay) == -1);

    // GetOutboundTarget stub: documented per-class defaults.
    assert(adapter->GetOutboundTarget(dilithion::net::OutboundClass::FullRelay) == 8);
    assert(adapter->GetOutboundTarget(dilithion::net::OutboundClass::BlockRelay) == 2);

    // GetConnections walks empty node list cleanly.
    auto connections = adapter->GetConnections();
    assert(connections.empty());

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — port-CPeerManager constructible with all 5 refs.
// THE LOAD-BEARING PR6.5b.0 ACCEPTANCE GATE: the construction-wiring gap
// (zero production instances of IConnectionManager / IAddressManager /
// IPeerScorer accessible to port-namespace consumers) is closed when this
// test compiles and completes without throwing.
//
// Implicit shutdown-ordering check: function-local unique_ptrs destruct in
// reverse order at scope exit. CPeerManager (constructed last) destructs
// first; its 5 non-owning refs are still valid. Then peer_scorer / addrman
// / adapter / connman / chainstate destruct in turn. Any non-owning-ref
// ordering bug would surface as a use-after-free here.
// ============================================================================
void test_port_cpeermanager_constructible_with_all_5_refs()
{
    std::cout << "  test_port_cpeermanager_constructible_with_all_5_refs..." << std::flush;

    // 1. ChainParams — pick a built-in. Regtest is cheapest (no real network).
    // Static keeps the value alive; ChainParams::Regtest() returns by value.
    static const ::Dilithion::ChainParams chainparams = ::Dilithion::ChainParams::Regtest();

    // 2. CChainState (for IChainSelector adapter) — fresh, no chain loaded.
    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector(chainstate);

    // 3. CConnman + CConnmanAdapter — wraps a real CConnman.
    CConnman connman;
    dilithion::net::port::CConnmanAdapter connman_adapter(connman);

    // 4. CAddrMan_v2 — production IAddressManager.
    dilithion::net::port::CAddrMan_v2 addrman;

    // 5. CPeerScorer — production IPeerScorer.
    dilithion::net::port::CPeerScorer scorer;

    // The construction itself is the test. If the constructor compiles
    // and runs, the wiring gap is closed.
    dilithion::net::port::CPeerManager pm(
        connman_adapter,    // IConnectionManager&
        addrman,            // IAddressManager&
        scorer,             // IPeerScorer&
        chain_selector,     // IChainSelector&
        chainparams);       // const ChainParams&

    // Sanity: vacuous-parity defaults from the skeleton are unchanged
    // by construction. PR6.5b.1a's lifecycle bodies (already in skeleton)
    // populate m_peers; PR6.5b.0 leaves them alone.
    assert(pm.IsInitialBlockDownload() == true);
    assert(pm.IsSynced() == false);
    assert(pm.GetHeadersSyncPeer() == -1);
    assert(pm.GetPeerCount() == 0);

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.0 — Wiring prep tests\n";
    std::cout << "  (4-test suite per active_contract.md)\n\n";

    try {
        test_addrman_construction();
        test_peer_scorer_construction();
        test_connman_adapter_construction();
        test_port_cpeermanager_constructible_with_all_5_refs();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 4 PR6.5b.0 wiring prep tests passed.\n";
    return 0;
}
