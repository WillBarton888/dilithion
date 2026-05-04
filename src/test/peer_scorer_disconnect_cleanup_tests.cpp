// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.3.3 F18 — port CPeerManager::OnPeerDisconnected must reset the shared
// scorer slot (Track B / cursor_v4_3_3_f18_brief.md). Without it, churn
// trips peer_scorer.cpp:128 (SIGABRT). Mirrors peer_scorer_tests.cpp style
// (void test_* + main, no Boost).

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <net/iconnection_manager.h>
#include <net/ipeer_scorer.h>
#include <net/net.h>
#include <net/peers.h>
#include <net/port/addrman_v2.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>

#include <cassert>
#include <cstddef>
#include <iostream>
#include <string>

namespace {

using ::dilithion::net::NodeId;
using ::dilithion::net::port::CPeerManager;
using ::dilithion::net::port::CPeerScorer;

class MockConnectionManager final : public ::dilithion::net::IConnectionManager {
public:
    void DisconnectNode(::dilithion::net::NodeId,
                        const std::string&) override {}
    ::dilithion::net::NodeId ConnectNode(const std::string&,
                                         ::dilithion::net::OutboundClass) override {
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
    bool PushMessage(::dilithion::net::NodeId,
                     const ::CNetMessage&) override { return true; }
};

struct PortPeerManagerFixture {
    static const ::Dilithion::ChainParams chainparams;
    Dilithion::ChainParams* prev_global_chainparams{nullptr};

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    MockConnectionManager mock_connman;
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer port_scorer;
    dilithion::net::port::CPeerManager pm;

    PortPeerManagerFixture()
        : prev_global_chainparams(Dilithion::g_chainParams),
          chain_selector(chainstate),
          pm(mock_connman, addrman, port_scorer, chain_selector, chainparams)
    {
        Dilithion::g_chainParams =
            const_cast<Dilithion::ChainParams*>(&chainparams);
    }

    ~PortPeerManagerFixture() { Dilithion::g_chainParams = prev_global_chainparams; }
};

const ::Dilithion::ChainParams PortPeerManagerFixture::chainparams =
    ::Dilithion::ChainParams::Regtest();

}  // namespace

void test_disconnect_resets_scorer_entry()
{
    std::cout << "  test_disconnect_resets_scorer_entry..." << std::flush;
    PortPeerManagerFixture fix;
    constexpr NodeId peer{1};
    fix.pm.OnPeerConnected(peer);
    fix.port_scorer.Misbehaving(peer, 25, "test");
    assert(fix.port_scorer.GetScoreMapSizeForTest() == 1u);
    fix.pm.OnPeerDisconnected(peer);
    assert(fix.port_scorer.GetScore(peer) == 0);
    assert(fix.port_scorer.GetScoreMapSizeForTest() == 0u);
    std::cout << " OK\n";
}

void test_many_disconnect_cycles_stay_under_scorer_bound()
{
    std::cout << "  test_many_disconnect_cycles_stay_under_scorer_bound..."
              << std::flush;
    PortPeerManagerFixture fix;
    constexpr size_t kIters =
        static_cast<size_t>(10 * ::CPeerManager::MAX_TOTAL_CONNECTIONS + 100);
    for (size_t i = 0; i < kIters; ++i) {
        const NodeId peer{static_cast<int>(100000 + static_cast<int>(i))};
        fix.pm.OnPeerConnected(peer);
        fix.port_scorer.Misbehaving(peer, 1, "churn");
        fix.pm.OnPeerDisconnected(peer);
    }
    assert(fix.port_scorer.GetScoreMapSizeForTest() == 0u);
    std::cout << " OK\n";
}

void test_reset_score_idempotent_unknown_peer()
{
    std::cout << "  test_reset_score_idempotent_unknown_peer..." << std::flush;
    PortPeerManagerFixture fix;
    constexpr NodeId ghost{999999};
    fix.pm.OnPeerDisconnected(ghost);
    fix.pm.OnPeerDisconnected(ghost);
    assert(fix.port_scorer.GetScoreMapSizeForTest() == 0u);
    fix.port_scorer.ResetScore(ghost);
    assert(fix.port_scorer.GetScoreMapSizeForTest() == 0u);
    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== F18 port OnPeerDisconnected / scorer cleanup tests ===\n"
              << std::endl;
    try {
        test_disconnect_resets_scorer_entry();
        test_many_disconnect_cycles_stay_under_scorer_bound();
        test_reset_score_idempotent_unknown_peer();
        std::cout << "\n=== All F18 disconnect cleanup tests passed (3) ===\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
