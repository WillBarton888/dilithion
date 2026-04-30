// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.7-b — Multithreaded lock-order invariants tests.
//
// Static-grep tests (peer_manager_lock_order_static_tests.cpp) prove the
// LEXICAL discipline: no peer-manager-mutex scope contains a callout to
// scorer/connman/chain_selector/addrman/g_node_context/hdr_mgr. Those tests
// are necessary but not sufficient — they cannot prove that the PRODUCTION
// code, exercised concurrently across many threads, is actually free of
// data races on the shared state behind those mutexes.
//
// These tests close that gap. They drive CPeerManager's public surface from
// multiple threads and rely on ThreadSanitizer (`make TSAN=1 …`) to surface
// any unsynchronised access, lock-order inversion, or torn read/write that
// the static analysis cannot see.
//
// Cases (6, per phase_6_decomposition_amendment_2026_04_30.md sub-stream b):
//   1. tick_with_concurrent_process_message
//      — N=4 threads spin ProcessMessage("verack", …) on a single peer
//        while a 5th thread spins Tick(). The two surfaces share
//        m_peers_mutex (peer state lookup) and m_sync_state_mutex (Tick's
//        block-download bookkeeping). Asserts no TSAN race.
//   2. mark_remove_block_in_flight_concurrent
//      — N=4 threads alternate MarkBlockInFlight / RemoveBlockInFlight on
//        rotating uint256 hashes for a single peer; a reader thread spins
//        GetBlocksInFlightForPeer. Asserts m_blocks_in_flight_mutex
//        actually serialises map mutations + per-peer counter increments.
//   3. peer_lifecycle_churn_with_tick
//      — 2 threads cycle OnPeerConnected / OnPeerDisconnected on disjoint
//        peer-id ranges; a 3rd thread spins Tick(); a 4th reads
//        GetPeerCount(). Stresses m_peers_mutex + the disconnect-purge of
//        m_blocks_in_flight + the IsSynced/m_synced flip surface.
//   4. send_messages_concurrent_across_peers
//      — N=8 peers connected; one thread per peer spins SendMessages(peer)
//        + a Tick thread runs concurrently. Stresses the per-peer
//        SendMessages path against Tick's scan over m_peers.
//   5. misbehavior_dispatch_concurrent_unknown_messages
//      — N=4 threads spin ProcessMessage("unknown_garbage", …) on disjoint
//        peer ids (each call ticks the port_scorer once). After all
//        threads join, the port_scorer's per-peer score must equal the
//        per-thread iteration count exactly — proves no lost-update in
//        the scoring path under contention.
//   6. mixed_full_load
//      — All five surfaces above driven concurrently for a fixed iteration
//        count. The harness mirrors the production thread-mix at peak
//        sync activity. Final-state assertions verify counters are
//        consistent.
//
// Iteration model: each thread runs kInnerIters operations. The test binary
// is intended to be re-executed × 100 times under TSAN to maximise race-
// detection probability per the decomposition's "× 100 iterations" stress
// requirement (a thin shell wrapper invokes the binary in a loop).
//
// Test pattern: void test_*() functions + custom main(). No Boost.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <crypto/randomx_hash.h>
#include <net/connman.h>
#include <net/iconnection_manager.h>
#include <net/ipeer_scorer.h>
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>
#include <net/protocol.h>
#include <net/serialize.h>
#include <uint256.h>

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

// Thread-safe IConnectionManager stub. The MockConnectionManager in
// peer_manager_misbehavior_tests.cpp uses std::vector<DisconnectCall> to
// record calls; that vector would race under contention. Here we only
// track counters via std::atomic so the mock itself contributes no races.
class ConcurrentMockConnman final : public ::dilithion::net::IConnectionManager {
public:
    std::atomic<int> disconnect_count{0};
    std::atomic<int> connect_count{0};

    void DisconnectNode(::dilithion::net::NodeId,
                        const std::string&) override {
        disconnect_count.fetch_add(1, std::memory_order_relaxed);
    }
    ::dilithion::net::NodeId ConnectNode(const std::string&,
                                         ::dilithion::net::OutboundClass) override {
        connect_count.fetch_add(1, std::memory_order_relaxed);
        return -1;
    }
    std::vector<::dilithion::net::ConnectionInfo> GetConnections() const override {
        return {};
    }
    int GetOutboundTarget(::dilithion::net::OutboundClass) const override { return 0; }
    bool IsBanned(const std::string&) const override { return false; }
    int GetConnectionCount(::dilithion::net::OutboundClass) const override { return 0; }
    int GetTotalInbound() const override { return 0; }
    int GetTotalOutbound() const override { return 0; }
};

// Iteration count per worker thread. Kept modest so the binary completes
// inside reasonable wall-clock; the × 100 outer loop (driven by the
// run_tsan_iterations.sh wrapper) provides the cumulative race-detection
// probability budget.
constexpr int kInnerIters = 2000;

// Synthesise a deterministic uint256 from a seed (avoids dependency on
// crypto RNG from many threads).
uint256 MakeHash(uint32_t seed) {
    uint256 h;
    h.SetNull();
    auto* bytes = h.begin();
    for (int i = 0; i < 4; ++i) {
        bytes[i]     = static_cast<uint8_t>((seed >>  0) & 0xff);
        bytes[i + 4] = static_cast<uint8_t>((seed >>  8) & 0xff);
        bytes[i + 8] = static_cast<uint8_t>((seed >> 16) & 0xff);
        bytes[i +12] = static_cast<uint8_t>((seed >> 24) & 0xff);
    }
    return h;
}

// Per-test fixture (mirrors MisbehaviorFixture's constructor surface).
// One scorer, one mock connman, one peer-manager. Tests instantiate
// freshly per case — no shared state across tests.
struct LockOrderFixture {
    static const ::Dilithion::ChainParams chainparams;
    Dilithion::ChainParams* prev_global_chainparams;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    ConcurrentMockConnman mock_connman;
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer scorer;
    dilithion::net::port::CPeerManager pm;

    LockOrderFixture()
        : prev_global_chainparams(Dilithion::g_chainParams),
          chain_selector(chainstate),
          pm(mock_connman, addrman, scorer, chain_selector, chainparams)
    {
        Dilithion::g_chainParams =
            const_cast<Dilithion::ChainParams*>(&chainparams);
    }

    ~LockOrderFixture() {
        Dilithion::g_chainParams = prev_global_chainparams;
    }
};

const ::Dilithion::ChainParams LockOrderFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

}  // anonymous namespace

// ============================================================================
// Test 1 — tick_with_concurrent_process_message
// ============================================================================
void test_tick_with_concurrent_process_message()
{
    std::cout << "  test_tick_with_concurrent_process_message..." << std::flush;

    LockOrderFixture fix;
    constexpr ::dilithion::net::NodeId kPeer = 100;
    fix.pm.OnPeerConnected(kPeer);

    std::atomic<bool> stop_tick{false};
    std::thread tick_thread([&] {
        while (!stop_tick.load(std::memory_order_relaxed)) {
            fix.pm.Tick();
        }
    });

    std::vector<std::thread> workers;
    for (int t = 0; t < 4; ++t) {
        workers.emplace_back([&] {
            for (int i = 0; i < kInnerIters; ++i) {
                std::vector<uint8_t> wire;
                CDataStream stream(wire);
                // verack has no body and exits early after handshake state
                // mutation; cheap repeatable inbound that exercises the
                // peer-state lookup path.
                (void)fix.pm.ProcessMessage(kPeer, "verack", stream);
            }
        });
    }

    for (auto& w : workers) w.join();
    stop_tick.store(true, std::memory_order_relaxed);
    tick_thread.join();

    // Sanity: peer is still tracked.
    assert(fix.pm.GetPeerCount() >= 1);
    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — mark_remove_block_in_flight_concurrent
// ============================================================================
void test_mark_remove_block_in_flight_concurrent()
{
    std::cout << "  test_mark_remove_block_in_flight_concurrent..." << std::flush;

    LockOrderFixture fix;
    constexpr ::dilithion::net::NodeId kPeer = 200;
    fix.pm.OnPeerConnected(kPeer);

    std::atomic<bool> stop_reader{false};
    std::thread reader_thread([&] {
        while (!stop_reader.load(std::memory_order_relaxed)) {
            volatile int n = fix.pm.GetBlocksInFlightForPeer(kPeer);
            (void)n;
        }
    });

    std::vector<std::thread> workers;
    for (int t = 0; t < 4; ++t) {
        workers.emplace_back([t, &fix] {
            for (int i = 0; i < kInnerIters; ++i) {
                // Disjoint hash space per worker so different threads do
                // not Mark+Remove the same key concurrently — that would
                // be intentional contention on the SAME key but is not
                // the contract of the API. We test inter-thread racing on
                // the MAP, not on individual entries.
                uint256 h = MakeHash(static_cast<uint32_t>(t * 100000 + i));
                fix.pm.MarkBlockInFlight(kPeer, h);
                fix.pm.RemoveBlockInFlight(kPeer, h);
            }
        });
    }

    for (auto& w : workers) w.join();
    stop_reader.store(true, std::memory_order_relaxed);
    reader_thread.join();

    // After all marks paired with removes, in-flight count for the peer
    // must be zero.
    assert(fix.pm.GetBlocksInFlightForPeer(kPeer) == 0);
    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — peer_lifecycle_churn_with_tick
// ============================================================================
void test_peer_lifecycle_churn_with_tick()
{
    std::cout << "  test_peer_lifecycle_churn_with_tick..." << std::flush;

    LockOrderFixture fix;

    std::atomic<bool> stop_tick{false};
    std::atomic<bool> stop_reader{false};

    std::thread tick_thread([&] {
        while (!stop_tick.load(std::memory_order_relaxed)) {
            fix.pm.Tick();
        }
    });
    std::thread reader_thread([&] {
        while (!stop_reader.load(std::memory_order_relaxed)) {
            volatile int n = fix.pm.GetPeerCount();
            (void)n;
        }
    });

    auto churn = [&fix](int peer_base) {
        for (int i = 0; i < kInnerIters; ++i) {
            ::dilithion::net::NodeId p = peer_base + (i % 16);
            fix.pm.OnPeerConnected(p);
            fix.pm.OnPeerDisconnected(p);
        }
    };

    std::thread w1(churn, 300);
    std::thread w2(churn, 500);
    w1.join();
    w2.join();
    stop_tick.store(true, std::memory_order_relaxed);
    stop_reader.store(true, std::memory_order_relaxed);
    tick_thread.join();
    reader_thread.join();

    // After full churn, no peer should remain (each Connect paired with
    // Disconnect on the same peer).
    assert(fix.pm.GetPeerCount() == 0);
    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — send_messages_concurrent_across_peers
// ============================================================================
void test_send_messages_concurrent_across_peers()
{
    std::cout << "  test_send_messages_concurrent_across_peers..." << std::flush;

    LockOrderFixture fix;
    constexpr int kNumPeers = 8;
    for (int i = 0; i < kNumPeers; ++i) {
        fix.pm.OnPeerConnected(700 + i);
    }

    std::atomic<bool> stop_tick{false};
    std::thread tick_thread([&] {
        while (!stop_tick.load(std::memory_order_relaxed)) {
            fix.pm.Tick();
        }
    });

    std::vector<std::thread> workers;
    for (int i = 0; i < kNumPeers; ++i) {
        workers.emplace_back([&fix, peer = 700 + i] {
            for (int j = 0; j < kInnerIters; ++j) {
                fix.pm.SendMessages(peer);
            }
        });
    }
    for (auto& w : workers) w.join();
    stop_tick.store(true, std::memory_order_relaxed);
    tick_thread.join();

    assert(fix.pm.GetPeerCount() == kNumPeers);
    std::cout << " OK\n";
}

// ============================================================================
// Test 5 — misbehavior_dispatch_concurrent_unknown_messages
// ============================================================================
void test_misbehavior_dispatch_concurrent_unknown_messages()
{
    std::cout << "  test_misbehavior_dispatch_concurrent_unknown_messages..."
              << std::flush;

    LockOrderFixture fix;
    constexpr int kNumPeers = 4;
    for (int i = 0; i < kNumPeers; ++i) {
        fix.pm.OnPeerConnected(900 + i);
    }

    constexpr int kHits = 500;
    std::vector<std::thread> workers;
    for (int i = 0; i < kNumPeers; ++i) {
        workers.emplace_back([&fix, peer = 900 + i] {
            for (int j = 0; j < kHits; ++j) {
                std::vector<uint8_t> wire;
                CDataStream stream(wire);
                (void)fix.pm.ProcessMessage(peer, "unknown_garbage", stream);
            }
        });
    }
    for (auto& w : workers) w.join();

    // Each peer's score must equal kHits exactly. UnknownMessage default
    // weight = 1, so kHits hits → score == kHits. No lost updates.
    for (int i = 0; i < kNumPeers; ++i) {
        const int score = fix.scorer.GetScore(900 + i);
        assert(score == kHits);
    }
    std::cout << " OK\n";
}

// ============================================================================
// Test 6 — mixed_full_load
// ============================================================================
void test_mixed_full_load()
{
    std::cout << "  test_mixed_full_load..." << std::flush;

    LockOrderFixture fix;
    constexpr int kCorePeers = 4;
    for (int i = 0; i < kCorePeers; ++i) {
        fix.pm.OnPeerConnected(1100 + i);
    }

    std::atomic<bool> stop_all{false};

    std::thread tick_thread([&] {
        while (!stop_all.load(std::memory_order_relaxed)) {
            fix.pm.Tick();
        }
    });

    std::thread inbound_thread([&] {
        for (int i = 0; i < kInnerIters; ++i) {
            std::vector<uint8_t> wire;
            CDataStream stream(wire);
            (void)fix.pm.ProcessMessage(1100 + (i % kCorePeers), "verack",
                                        stream);
        }
    });

    std::thread mark_thread([&] {
        for (int i = 0; i < kInnerIters; ++i) {
            uint256 h = MakeHash(static_cast<uint32_t>(700000 + i));
            fix.pm.MarkBlockInFlight(1100 + (i % kCorePeers), h);
            fix.pm.RemoveBlockInFlight(1100 + (i % kCorePeers), h);
        }
    });

    std::thread send_thread([&] {
        for (int i = 0; i < kInnerIters; ++i) {
            fix.pm.SendMessages(1100 + (i % kCorePeers));
        }
    });

    std::thread churn_thread([&] {
        for (int i = 0; i < kInnerIters / 4; ++i) {
            ::dilithion::net::NodeId p = 1200 + (i % 8);
            fix.pm.OnPeerConnected(p);
            fix.pm.OnPeerDisconnected(p);
        }
    });

    inbound_thread.join();
    mark_thread.join();
    send_thread.join();
    churn_thread.join();
    stop_all.store(true, std::memory_order_relaxed);
    tick_thread.join();

    // The 4 core peers should still be present (Connect/Disconnect churn
    // operated on disjoint peer ids 1200-1207, leaving the core peers
    // untouched). All Mark→Remove pairs must net to zero in-flight.
    assert(fix.pm.GetPeerCount() == kCorePeers);
    for (int i = 0; i < kCorePeers; ++i) {
        assert(fix.pm.GetBlocksInFlightForPeer(1100 + i) == 0);
    }
    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.7-b — Multithreaded lock-order invariants tests\n";
    std::cout << "  (6-case suite — TSAN race-detection harness)\n\n";

    try {
        test_tick_with_concurrent_process_message();
        test_mark_remove_block_in_flight_concurrent();
        test_peer_lifecycle_churn_with_tick();
        test_send_messages_concurrent_across_peers();
        test_misbehavior_dispatch_concurrent_unknown_messages();
        test_mixed_full_load();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 6 PR6.5b.7-b multithreaded lock-order tests passed.\n";
    return 0;
}
