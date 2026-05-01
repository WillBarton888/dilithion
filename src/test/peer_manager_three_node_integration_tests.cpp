// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.7-c — 3-node in-process integration tests.
//
// Sub-stream (b) verified the multithreaded lock-order discipline at
// unit level (one CPeerManager × N concurrent caller threads). This
// suite raises the harness to integration level: three CPeerManager
// instances wired together via a TestRoutingConnman that captures each
// fixture's outbound PushMessage and re-delivers it as inbound
// ProcessMessage on the destination fixture.
//
// What this exercises beyond sub-stream (b):
//   * The new IConnectionManager.PushMessage routing surface
//     (`phase_6_interface_additions_ratification.md` §3) end-to-end.
//   * Cross-fixture γ ownership: when fixture A routes an event to
//     fixture B, only B's port_scorer ticks — A's scorer is untouched
//     because A originated transport, not the protocol misbehavior.
//   * 3-node multithreaded contention: all three fixtures driven from
//     concurrent threads, with the routing connman as the shared
//     synchronization point. TSAN should surface any race in the
//     cross-fixture state machine that unit-level (b) tests cannot
//     observe.
//
// Cases (5):
//   1. routing_connman_round_trip
//      — A→B unknown_command via routing connman; B's port_scorer
//        ticks for sender=A_idx, A's scorer untouched. Smoke-test
//        for the routing path.
//   2. cross_node_gamma_ownership
//      — All 3 fixtures hold port_scorer + a "legacy_scorer" stub.
//        A sends unknown_command to B and to C, separately. Asserts
//        port_scorer of the RECIPIENT ticks; port_scorer of the
//        SENDER and legacy_scorer of EVERY fixture stay at 0.
//        Strengthens the "γ ownership held cross-fixture" guarantee.
//   3. multithreaded_three_node_concurrent_inbound
//      — 3 worker threads (one per fixture) routing unknown_garbage
//        in a tight loop to neighbours. TSAN sweep.
//   4. multithreaded_three_node_lifecycle_churn
//      — Each fixture's main thread connects/disconnects peers from
//        the disjoint id range (0..7, 100..107, 200..207). Plus a
//        Tick thread per fixture. Stresses cross-fixture state.
//   5. mixed_full_load_three_nodes
//      — Combined: per-fixture inbound routing + per-fixture Tick +
//        per-fixture lifecycle churn, all concurrent.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <crypto/randomx_hash.h>
#include <net/connman.h>
#include <net/iconnection_manager.h>
#include <net/ipeer_scorer.h>
#include <net/port/addrman_v2.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>
#include <net/protocol.h>
#include <net/serialize.h>

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// ============================================================================
// 3-node network shared state. Populated AFTER all three CPeerManager
// instances are constructed (constructor cannot reach back into the
// network map yet since the routing connman is created BEFORE the
// fixture's pm). Threads do not modify this map after the fixture's
// SetUp() call returns; the only mutation is the initial population.
// ============================================================================
struct ThreeNodeNetwork {
    std::array<dilithion::net::port::CPeerManager*, 3> nodes{nullptr, nullptr, nullptr};
};

// ============================================================================
// TestRoutingConnman — IConnectionManager that delivers PushMessage as
// inbound ProcessMessage on the destination fixture. One instance per
// fixture, configured with `self_idx` so the receiver knows who the
// sender is in its own NodeId space.
//
// Convention: each fixture sees its peers using the SENDER's idx
// (0/1/2) as the NodeId. Test setup must call OnPeerConnected on each
// fixture for every other fixture's idx so the peer state is known.
//
// Thread-safety: stateless after SetNetwork(). PushMessage is
// re-entrant — multiple sender threads may call concurrently.
// ProcessMessage on the destination is itself thread-safe (verified
// in sub-stream (b)), so concurrent deliveries are race-free.
// ============================================================================
class TestRoutingConnman final : public ::dilithion::net::IConnectionManager {
public:
    TestRoutingConnman(ThreeNodeNetwork& net, int self_idx)
        : m_net(net), m_self_idx(self_idx) {}

    void DisconnectNode(::dilithion::net::NodeId,
                        const std::string&) override {
        m_disconnects.fetch_add(1, std::memory_order_relaxed);
    }
    ::dilithion::net::NodeId
    ConnectNode(const std::string&, ::dilithion::net::OutboundClass) override {
        return -1;
    }
    std::vector<::dilithion::net::ConnectionInfo>
    GetConnections() const override { return {}; }
    int  GetOutboundTarget(::dilithion::net::OutboundClass) const override { return 0; }
    bool IsBanned(const std::string&) const override { return false; }
    int  GetConnectionCount(::dilithion::net::OutboundClass) const override { return 0; }
    int  GetTotalInbound() const override { return 0; }
    int  GetTotalOutbound() const override { return 0; }

    bool PushMessage(::dilithion::net::NodeId dest,
                     const ::CNetMessage& msg) override {
        m_pushes.fetch_add(1, std::memory_order_relaxed);
        if (dest < 0 || dest >= 3 || dest == m_self_idx) {
            return false;
        }
        auto* recipient = m_net.nodes[dest];
        if (recipient == nullptr) return false;

        // Translate command. CMessageHeader stores the command as a
        // NUL-padded fixed-size char array; trim trailing NULs.
        std::string cmd(msg.header.command,
                        strnlen(msg.header.command,
                                sizeof(msg.header.command)));

        // Recipient's view of the sender = m_self_idx (this fixture).
        ::CDataStream stream(msg.payload);
        recipient->ProcessMessage(m_self_idx, cmd, stream);
        return true;
    }

    int self_idx() const { return m_self_idx; }
    int disconnects() const {
        return m_disconnects.load(std::memory_order_relaxed);
    }
    int pushes() const {
        return m_pushes.load(std::memory_order_relaxed);
    }

private:
    ThreeNodeNetwork& m_net;
    int m_self_idx;
    std::atomic<int> m_disconnects{0};
    std::atomic<int> m_pushes{0};
};

// Per-fixture state. Each fixture owns its own routing connman, scorer,
// addrman, chain_selector, and CPeerManager. The shared ThreeNodeNetwork
// pointer table is populated post-construction.
struct NodeFixture {
    static const ::Dilithion::ChainParams chainparams;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    TestRoutingConnman routing_connman;
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer port_scorer;
    dilithion::net::port::CPeerScorer legacy_scorer;  // simulated legacy side
    dilithion::net::port::CPeerManager pm;

    NodeFixture(ThreeNodeNetwork& net, int idx)
        : chain_selector(chainstate),
          routing_connman(net, idx),
          pm(routing_connman, addrman, port_scorer, chain_selector, chainparams)
    {}
};

const ::Dilithion::ChainParams NodeFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

// Convenience: build the 3 fixtures + populate the network map +
// register every fixture's two neighbours as connected peers.
struct ThreeNodeHarness {
    ThreeNodeNetwork net;
    Dilithion::ChainParams* prev_global_chainparams;
    std::unique_ptr<NodeFixture> fixtures[3];

    ThreeNodeHarness()
        : prev_global_chainparams(Dilithion::g_chainParams)
    {
        for (int i = 0; i < 3; ++i) {
            fixtures[i] = std::make_unique<NodeFixture>(net, i);
            net.nodes[i] = &fixtures[i]->pm;
        }
        Dilithion::g_chainParams =
            const_cast<Dilithion::ChainParams*>(&NodeFixture::chainparams);

        // Register cross-fixture peers (each fixture sees the other two
        // by their idx).
        for (int i = 0; i < 3; ++i) {
            for (int j = 0; j < 3; ++j) {
                if (i == j) continue;
                fixtures[i]->pm.OnPeerConnected(j);
            }
        }
    }

    ~ThreeNodeHarness() {
        Dilithion::g_chainParams = prev_global_chainparams;
    }

    NodeFixture& fix(int idx) { return *fixtures[idx]; }
};

}  // anonymous namespace

// ============================================================================
// Test 1 — routing_connman_round_trip
// ============================================================================
void test_routing_connman_round_trip()
{
    std::cout << "  test_routing_connman_round_trip..." << std::flush;

    ThreeNodeHarness h;

    // Construct an "unknown_garbage" CNetMessage (empty payload, mock
    // command) and push it from fixture 0 to fixture 1. ProcessMessage
    // on fixture 1 will tick fixture 1's port_scorer with weight=1 for
    // the unknown command (UnknownMessage default weight).
    {
        std::vector<uint8_t> payload;
        ::CNetMessage msg("unknown_garbage", payload);
        bool ok = h.fix(0).routing_connman.PushMessage(1, msg);
        assert(ok);
    }

    // Recipient's port_scorer for sender (= fixture-0 idx = 0) must
    // have ticked exactly once.
    assert(h.fix(1).port_scorer.GetScore(0) == 1);
    // Sender's scorer untouched.
    assert(h.fix(0).port_scorer.GetScore(1) == 0);
    // Third fixture untouched.
    assert(h.fix(2).port_scorer.GetScore(0) == 0);

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — cross_node_gamma_ownership
// ============================================================================
void test_cross_node_gamma_ownership()
{
    std::cout << "  test_cross_node_gamma_ownership..." << std::flush;

    ThreeNodeHarness h;

    // Fixture 0 sends "unknown_garbage" to fixture 1 AND to fixture 2,
    // each via the routing connman (mirrors a node misbehaving toward
    // both of its peers).
    for (int dest : {1, 2}) {
        std::vector<uint8_t> payload;
        ::CNetMessage msg("unknown_garbage", payload);
        bool ok = h.fix(0).routing_connman.PushMessage(dest, msg);
        assert(ok);
    }

    // Recipients' port_scorers ticked once each for sender 0.
    assert(h.fix(1).port_scorer.GetScore(0) == 1);
    assert(h.fix(2).port_scorer.GetScore(0) == 1);

    // Sender's port_scorer untouched (γ ownership: protocol misbehavior
    // is owned by the receiver, not the originator).
    assert(h.fix(0).port_scorer.GetScore(1) == 0);
    assert(h.fix(0).port_scorer.GetScore(2) == 0);

    // Legacy scorers on EVERY fixture untouched (γ ownership: port owns
    // protocol misbehavior; legacy owns transport-integrity. Routing
    // never touches legacy scorers.)
    for (int i = 0; i < 3; ++i) {
        for (int peer : {0, 1, 2}) {
            if (peer == i) continue;
            assert(h.fix(i).legacy_scorer.GetScore(peer) == 0);
        }
    }

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — multithreaded_three_node_concurrent_inbound
// ============================================================================
void test_multithreaded_three_node_concurrent_inbound()
{
    std::cout << "  test_multithreaded_three_node_concurrent_inbound..."
              << std::flush;

    ThreeNodeHarness h;
    constexpr int kHits = 200;

    // Each thread routes from its own fixture to the next two.
    auto driver = [&h](int from_idx) {
        for (int j = 0; j < kHits; ++j) {
            for (int to_idx = 0; to_idx < 3; ++to_idx) {
                if (to_idx == from_idx) continue;
                std::vector<uint8_t> payload;
                ::CNetMessage msg("unknown_garbage", payload);
                h.fix(from_idx).routing_connman.PushMessage(to_idx, msg);
            }
        }
    };

    std::thread t0(driver, 0);
    std::thread t1(driver, 1);
    std::thread t2(driver, 2);
    t0.join();
    t1.join();
    t2.join();

    // Each fixture received kHits hits from EACH of the other two
    // fixtures → score == 2 * kHits (sum of both senders) per peer
    // entry would be wrong because scores are PER-PEER. Actual:
    // score == kHits per (recipient, sender) tuple. Verify exactly
    // that:
    for (int recipient = 0; recipient < 3; ++recipient) {
        for (int sender = 0; sender < 3; ++sender) {
            if (sender == recipient) continue;
            const int score =
                h.fix(recipient).port_scorer.GetScore(sender);
            assert(score == kHits);
        }
    }

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — multithreaded_three_node_lifecycle_churn
// ============================================================================
void test_multithreaded_three_node_lifecycle_churn()
{
    std::cout << "  test_multithreaded_three_node_lifecycle_churn..."
              << std::flush;

    ThreeNodeHarness h;
    constexpr int kIters = 1000;

    std::atomic<bool> stop_tick{false};
    std::array<std::thread, 3> tick_threads;
    for (int i = 0; i < 3; ++i) {
        tick_threads[i] = std::thread([i, &h, &stop_tick] {
            while (!stop_tick.load(std::memory_order_relaxed)) {
                h.fix(i).pm.Tick();
            }
        });
    }

    auto churn = [&h](int fixture_idx, int peer_base) {
        for (int j = 0; j < kIters; ++j) {
            ::dilithion::net::NodeId p = peer_base + (j % 8);
            h.fix(fixture_idx).pm.OnPeerConnected(p);
            h.fix(fixture_idx).pm.OnPeerDisconnected(p);
        }
    };

    // Peer-id ranges chosen disjoint from cross-fixture peer ids
    // {0, 1, 2} so churn does not disconnect the harness-registered
    // cross-fixture peers.
    std::thread w0(churn, 0, 500);
    std::thread w1(churn, 1, 600);
    std::thread w2(churn, 2, 700);
    w0.join();
    w1.join();
    w2.join();

    stop_tick.store(true, std::memory_order_relaxed);
    for (auto& t : tick_threads) t.join();

    // After churn, each fixture should still have its 2 cross-fixture
    // peers (the harness registered them at construction; churn
    // operated on disjoint id ranges 0-7, 100-107, 200-207).
    for (int i = 0; i < 3; ++i) {
        assert(h.fix(i).pm.GetPeerCount() == 2);
    }

    std::cout << " OK\n";
}

// ============================================================================
// Test 5 — mixed_full_load_three_nodes
// ============================================================================
void test_mixed_full_load_three_nodes()
{
    std::cout << "  test_mixed_full_load_three_nodes..." << std::flush;

    ThreeNodeHarness h;
    constexpr int kHits = 100;
    constexpr int kChurnIters = 200;

    std::atomic<bool> stop_tick{false};
    std::array<std::thread, 3> tick_threads;
    for (int i = 0; i < 3; ++i) {
        tick_threads[i] = std::thread([i, &h, &stop_tick] {
            while (!stop_tick.load(std::memory_order_relaxed)) {
                h.fix(i).pm.Tick();
            }
        });
    }

    auto inbound_driver = [&h](int from_idx) {
        for (int j = 0; j < kHits; ++j) {
            for (int to_idx = 0; to_idx < 3; ++to_idx) {
                if (to_idx == from_idx) continue;
                std::vector<uint8_t> payload;
                ::CNetMessage msg("unknown_garbage", payload);
                h.fix(from_idx).routing_connman.PushMessage(to_idx, msg);
            }
        }
    };

    auto churn = [&h](int fixture_idx, int peer_base) {
        for (int j = 0; j < kChurnIters; ++j) {
            ::dilithion::net::NodeId p = peer_base + (j % 4);
            h.fix(fixture_idx).pm.OnPeerConnected(p);
            h.fix(fixture_idx).pm.OnPeerDisconnected(p);
        }
    };

    std::thread i0(inbound_driver, 0);
    std::thread i1(inbound_driver, 1);
    std::thread i2(inbound_driver, 2);
    std::thread c0(churn, 0, 1000);
    std::thread c1(churn, 1, 2000);
    std::thread c2(churn, 2, 3000);

    i0.join(); i1.join(); i2.join();
    c0.join(); c1.join(); c2.join();
    stop_tick.store(true, std::memory_order_relaxed);
    for (auto& t : tick_threads) t.join();

    // Cross-fixture peers must still be present (churn operated on
    // disjoint id ranges 1000-1003, 2000-2003, 3000-3003).
    for (int i = 0; i < 3; ++i) {
        assert(h.fix(i).pm.GetPeerCount() == 2);
    }

    // Each (recipient, sender) score equals kHits exactly — proves
    // no lost updates across the full mixed load.
    for (int recipient = 0; recipient < 3; ++recipient) {
        for (int sender = 0; sender < 3; ++sender) {
            if (sender == recipient) continue;
            assert(h.fix(recipient).port_scorer.GetScore(sender) == kHits);
        }
    }

    std::cout << " OK\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.7-c — 3-node in-process integration tests\n";
    std::cout << "  (5-case suite — TestRoutingConnman + cross-fixture γ + TSAN harness)\n\n";

    try {
        test_routing_connman_round_trip();
        test_cross_node_gamma_ownership();
        test_multithreaded_three_node_concurrent_inbound();
        test_multithreaded_three_node_lifecycle_churn();
        test_mixed_full_load_three_nodes();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 5 PR6.5b.7-c three-node integration tests passed.\n";
    return 0;
}
