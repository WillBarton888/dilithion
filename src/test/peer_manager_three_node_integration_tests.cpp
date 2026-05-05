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
// Cases (7):
//   1. routing_connman_round_trip
//      — A→B "junk_msg" via routing connman; B's port_scorer
//        ticks for sender=A_idx, A's scorer untouched. Smoke-test
//        for the routing path. (Command must be ≤11 chars to fit
//        the 12-byte CMessageHeader.command field without
//        truncation; per PR6.5b.7-c-RT-MEDIUM-1.)
//   2. cross_node_gamma_ownership
//      — A sends "junk_msg" to B and to C, separately. Asserts
//        port_scorer of the RECIPIENT ticks; port_scorer of the
//        SENDER untouched. Legacy-side transport-integrity
//        scoring intentionally NOT asserted at integration level
//        (port-only fixtures cannot exercise legacy outbound paths
//        under γ); unit-level coverage at parity gate Test 13
//        (`ParityGate_TransportIntegrity_LegacyScoresOnly_RealConnmanWiring`)
//        in peer_manager_misbehavior_tests.cpp. See
//        PR6.5b.7-c-RT-HIGH-2 ledger entry.
//   3. multithreaded_three_node_concurrent_inbound
//      — 3 worker threads (one per fixture) routing "junk_msg"
//        in a tight loop to neighbours. Asserts score == kHits
//        exactly per (recipient, sender) tuple → no lost updates.
//   4. multithreaded_three_node_lifecycle_churn
//      — Each fixture's main thread connects/disconnects peers from
//        disjoint id ranges (500..507, 600..607, 700..707) — chosen
//        disjoint from cross-fixture peer ids {0,1,2}. Plus a Tick
//        thread per fixture. Stresses cross-fixture state.
//   5. mixed_full_load_three_nodes
//      — Combined: per-fixture inbound routing + per-fixture Tick +
//        per-fixture lifecycle churn, all concurrent.
//   6. test_port_peer_manager_ibd_catchup_under_usenewpeerman_v1
//      — v4.3.3: ProcessHeadersMessage → QueueRawHeaders → async mirror
//        to port CPeerManager; RequestNextBlocks arms; blocks advance tip.
//   7. test_port_peer_manager_ibd_negative_without_mirror_dynamic_cast_v1
//      — Negative: sync_coordinator is not port CPeerManager → mirror
//        skipped; port height stale; no in-flight block requests.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <net/connman.h>
#include <net/headers_manager.h>
#include <net/iconnection_manager.h>
#include <net/ipeer_scorer.h>
#include <net/net.h>
#include <net/node.h>
#include <net/peers.h>
#include <net/port/addrman_v2.h>
#include <net/port/connman_adapter.h>
#include <net/port/peer_manager.h>
#include <net/port/peer_scorer.h>
#include <net/port/sync_coordinator.h>
#include <net/protocol.h>
#include <net/serialize.h>
#include <node/genesis.h>
#include <primitives/block.h>

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern CChainState g_chainstate;

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
//
// Note: this fixture intentionally does NOT carry a `legacy_scorer`
// member — see PR6.5b.7-c-RT-HIGH-2 (red-team finding 2026-05-01).
// Cross-fixture transport-integrity scoring (legacy owns transport
// under γ) requires real ::CPeerManager wiring which is heavier than
// 3 in-process port fixtures; deferred to Phase 7+. The unit-level
// parity gate `ParityGate_TransportIntegrity_LegacyScoresOnly_RealConnmanWiring`
// (peer_manager_misbehavior_tests.cpp Test 13) covers the legacy-side
// transport-integrity scoring assertion at the unit level.
struct NodeFixture {
    static const ::Dilithion::ChainParams chainparams;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter chain_selector;
    TestRoutingConnman routing_connman;
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer port_scorer;
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
// v4.3.3 — Port peer manager IBD mirror (commit 415353e) integration
//
// Producer path (net.cpp:299–398): CNetMessageProcessor::ProcessMessage
// routes "headers" → ProcessHeadersMessage → dilv-node SetHeadersHandler
// (QueueRawHeadersForProcessing) → HeaderProcessorThread → mirror onto
// port::CPeerManager when sync_coordinator is the port manager.
//
// Consumer path: port::CPeerManager::Tick → RequestNextBlocks issues
// outbound getdata (MSG_BLOCK_INV) via IConnectionManager::PushMessage;
// we record pushes and assert payload matches peer_manager.cpp's
// placeholder hash encoding for regtest (same bytes production emits
// today; real header hashes are filled on a different code path).
//
// Uses global g_chainstate (CHeadersManager consults it during header
// validation). Tests run after the PR6.5b.7-c harness so g_chainParams
// churn from ThreeNodeHarness is already restored.
// ============================================================================
namespace ibdl_port_mirror_test {

constexpr int kPeerA = 501;
constexpr int kHeaderChainLen = 6;
constexpr int kPollTimeoutMs = 60000;

static Dilithion::ChainParams s_regtestParams = Dilithion::ChainParams::Regtest();

NetProtocol::CAddress MakeTestAddress(uint16_t port = 8444)
{
    NetProtocol::CAddress addr;
    std::memset(addr.ip, 0, 10);
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    addr.ip[12] = 127;
    addr.ip[13] = 0;
    addr.ip[14] = 0;
    addr.ip[15] = 1;
    addr.port = port;
    addr.services = 0;
    addr.time = 0;
    return addr;
}

bool PollUntil(int timeout_ms, const std::function<bool()>& pred)
{
    const auto t0 = std::chrono::steady_clock::now();
    while (true) {
        if (pred()) {
            return true;
        }
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0)
                .count() >= timeout_ms) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

std::vector<CBlockHeader> BuildVdfHeaderExtension(const uint256& genesis_hash)
{
    std::vector<CBlockHeader> out;
    uint256 prev = genesis_hash;
    for (int i = 1; i <= kHeaderChainLen; ++i) {
        CBlockHeader h;
        h.nVersion = CBlockHeader::VDF_VERSION;
        h.hashPrevBlock = prev;
        h.hashMerkleRoot = uint256();
        h.nTime = 1700000500u + static_cast<uint32_t>(i);
        h.nBits = 0x1d00ffff;
        h.nNonce = 0;
        std::memset(h.vdfOutput.data, 0, 32);
        std::memset(h.vdfProofHash.data, 0, 32);
        h.vdfOutput.data[0] = static_cast<uint8_t>(i & 0xff);
        out.push_back(h);
        prev = h.GetHash();
    }
    return out;
}

bool InitRegtestGenesisOnGlobalChainstate()
{
    g_chainstate.Cleanup();
    Dilithion::g_chainParams = &s_regtestParams;

    const CBlock genesis = Genesis::CreateGenesisBlock();
    const uint256 gh = genesis.GetHash();

    auto pindex = std::make_unique<CBlockIndex>(genesis);
    pindex->phashBlock = gh;
    pindex->pprev = nullptr;
    pindex->nHeight = 0;
    pindex->nChainWork = pindex->GetBlockProof();
    pindex->nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;

    if (!g_chainstate.AddBlockIndex(gh, std::move(pindex))) {
        return false;
    }
    CBlockIndex* tip = g_chainstate.GetBlockIndex(gh);
    if (!tip) {
        return false;
    }
    bool reorg = false;
    return g_chainstate.ActivateBestChain(tip, genesis, reorg);
}

void ClearGlobalNodeContext()
{
    g_node_context.headers_manager.reset();
    if (g_node_context.connman) {
        g_node_context.connman->RegisterPortPeerManager(nullptr);
    }
    g_node_context.sync_coordinator.reset();
    g_node_context.message_processor = nullptr;
    g_node_context.connman.reset();
    g_node_context.peer_manager.reset();
    g_node_context.chain_selector.reset();
    g_node_context.chainstate = nullptr;
}

struct DummySyncCoordinator final : dilithion::net::port::ISyncCoordinator {
    bool IsInitialBlockDownload() const override { return true; }
    bool IsSynced() const override { return false; }
    int GetHeadersSyncPeer() const override { return -1; }
    void OnOrphanBlockReceived() override {}
    void OnBlockConnected() override {}
    void Tick() override {}
};

// Mirrors peer_manager.cpp RequestNextBlocks placeholder encoding
// (peer id in upper 8 bytes of first 16 bytes, target height in lower 8).
uint256 ExpectedPlaceholderInvHash(dilithion::net::NodeId peer, int target_height)
{
    uint256 placeholder;
    const uint64_t lo = static_cast<uint64_t>(target_height);
    const uint64_t hi = static_cast<uint64_t>(static_cast<uint32_t>(peer));
    for (int b = 0; b < 8; ++b) {
        placeholder.data[b] = static_cast<uint8_t>((lo >> (8 * b)) & 0xff);
        placeholder.data[8 + b] = static_cast<uint8_t>((hi >> (8 * b)) & 0xff);
    }
    return placeholder;
}

// Wraps CConnmanAdapter to record outbound getdata (command + inv list)
// while still delivering to the legacy connman (production-shaped path).
class RecordingConnmanAdapter final : public dilithion::net::IConnectionManager {
public:
    struct GetDataPush {
        dilithion::net::NodeId peer{};
        std::vector<std::pair<uint32_t, uint256>> invs;
    };
    std::vector<GetDataPush> getdata_pushes;

    explicit RecordingConnmanAdapter(CConnman& connman)
        : m_inner(connman) {}

    void DisconnectNode(dilithion::net::NodeId peer,
                        const std::string& reason) override {
        m_inner.DisconnectNode(peer, reason);
    }
    dilithion::net::NodeId ConnectNode(const std::string& addr,
                                       dilithion::net::OutboundClass cls) override {
        return m_inner.ConnectNode(addr, cls);
    }
    std::vector<dilithion::net::ConnectionInfo> GetConnections() const override {
        return m_inner.GetConnections();
    }
    int GetOutboundTarget(dilithion::net::OutboundClass cls) const override {
        return m_inner.GetOutboundTarget(cls);
    }
    bool IsBanned(const std::string& addr) const override {
        return m_inner.IsBanned(addr);
    }
    int GetConnectionCount(dilithion::net::OutboundClass cls) const override {
        return m_inner.GetConnectionCount(cls);
    }
    int GetTotalInbound() const override { return m_inner.GetTotalInbound(); }
    int GetTotalOutbound() const override { return m_inner.GetTotalOutbound(); }

    bool PushMessage(dilithion::net::NodeId peer, const CNetMessage& msg) override {
        std::string cmd(msg.header.command,
                        strnlen(msg.header.command, sizeof(msg.header.command)));
        if (cmd == "getdata") {
            try {
                CDataStream s(msg.payload);
                const uint64_t n = s.ReadCompactSize();
                GetDataPush cap;
                cap.peer = peer;
                cap.invs.reserve(static_cast<size_t>(n));
                for (uint64_t i = 0; i < n; ++i) {
                    const uint32_t typ = s.ReadUint32();
                    const uint256 h = s.ReadUint256();
                    cap.invs.push_back({typ, h});
                }
                getdata_pushes.push_back(std::move(cap));
            } catch (...) {
                // Leave getdata_pushes unchanged; forward still runs; test will fail on assert.
            }
        }
        return m_inner.PushMessage(peer, msg);
    }

private:
    dilithion::net::port::CConnmanAdapter m_inner;
};

void RunPositiveMirrorPath()
{
    assert(InitRegtestGenesisOnGlobalChainstate());

    g_node_context.chainstate = &g_chainstate;
    g_node_context.chain_selector =
        std::make_unique<dilithion::consensus::port::ChainSelectorAdapter>(g_chainstate);

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.connman = std::make_unique<CConnman>();
    g_node_context.connman->SetTestPeerManager(*g_node_context.peer_manager);

    RecordingConnmanAdapter recording_conn(*g_node_context.connman);
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer scorer;
    auto* selector = static_cast<dilithion::consensus::port::ChainSelectorAdapter*>(
        g_node_context.chain_selector.get());

    auto port_pm = std::make_unique<dilithion::net::port::CPeerManager>(
        recording_conn, addrman, scorer, *selector, s_regtestParams);
    dilithion::net::port::CPeerManager* port_raw = port_pm.get();

    g_node_context.connman->RegisterPortPeerManager(port_raw);
    g_node_context.sync_coordinator =
        std::unique_ptr<dilithion::net::port::ISyncCoordinator>(std::move(port_pm));

    g_node_context.headers_manager = std::make_unique<CHeadersManager>();

    auto msg_proc = std::make_unique<CNetMessageProcessor>(*g_node_context.peer_manager);
    g_node_context.message_processor = msg_proc.get();

    msg_proc->SetHeadersHandler([](int peer_id, const std::vector<CBlockHeader>& headers) {
        if (headers.empty()) {
            return;
        }
        (void)g_node_context.headers_manager->QueueRawHeadersForProcessing(
            peer_id, std::vector<CBlockHeader>(headers));
    });

    NetProtocol::CAddress addr = MakeTestAddress();
    auto test_node = std::make_unique<CNode>(kPeerA, addr, /*inbound=*/false);
    test_node->state.store(CNode::STATE_HANDSHAKE_COMPLETE);

    assert(g_node_context.connman->DispatchPeerConnected(
        kPeerA, test_node.get(), addr, /*inbound=*/false));

    port_raw->CatchUpRegisteredLegacyPeers();

    const CBlock genesis = Genesis::CreateGenesisBlock();
    const uint256 genesis_hash = genesis.GetHash();
    const std::vector<CBlockHeader> ext = BuildVdfHeaderExtension(genesis_hash);

    const CNetMessage hdr_msg = msg_proc->CreateHeadersMessage(ext);
    assert(msg_proc->ProcessMessage(kPeerA, hdr_msg));

    assert(PollUntil(kPollTimeoutMs, [&]() {
        return g_node_context.headers_manager &&
               g_node_context.headers_manager->GetBestHeight() >= kHeaderChainLen;
    }));

    assert(port_raw->GetPeerBestKnownBlockHeight(kPeerA) == kHeaderChainLen);

    port_raw->Tick();
    assert(port_raw->GetBlocksInFlightForPeer(kPeerA) > 0);

    // RequestNextBlocks must issue at least one outbound getdata whose
    // MSG_BLOCK_INV hashes match the production placeholder encoding for
    // heights (active+1 ..) capped by regtest per-peer limit (4).
    assert(!recording_conn.getdata_pushes.empty());
    const auto& gd0 = recording_conn.getdata_pushes.front();
    assert(gd0.peer == kPeerA);
    assert(!gd0.invs.empty());
    constexpr int kRegtestCap = 4;
    const int expect_invs = std::min(kHeaderChainLen, kRegtestCap);
    assert(static_cast<int>(gd0.invs.size()) == expect_invs);
    for (int i = 0; i < expect_invs; ++i) {
        assert(gd0.invs[static_cast<size_t>(i)].first == NetProtocol::MSG_BLOCK_INV);
        const int target_h = 1 + i;
        assert(gd0.invs[static_cast<size_t>(i)].second ==
               ExpectedPlaceholderInvHash(kPeerA, target_h));
    }

    for (const CBlockHeader& hdr : ext) {
        CBlock block(hdr);
        CDataStream blk_stream;
        blk_stream.WriteInt32(block.nVersion);
        blk_stream.WriteUint256(block.hashPrevBlock);
        blk_stream.WriteUint256(block.hashMerkleRoot);
        blk_stream.WriteUint32(block.nTime);
        blk_stream.WriteUint32(block.nBits);
        blk_stream.WriteUint32(block.nNonce);
        if (block.IsVDFBlock()) {
            blk_stream.WriteUint256(block.vdfOutput);
            blk_stream.WriteUint256(block.vdfProofHash);
        }
        blk_stream.WriteCompactSize(0);
        (void)port_raw->ProcessMessage(kPeerA, "block", blk_stream);
    }

    assert(g_chainstate.GetHeight() == kHeaderChainLen);

    msg_proc->SetHeadersHandler(nullptr);
    msg_proc.reset();
    ClearGlobalNodeContext();
    g_chainstate.Cleanup();
    Dilithion::g_chainParams = nullptr;
}

void RunNegativeNoMirrorDynamicCast()
{
    assert(InitRegtestGenesisOnGlobalChainstate());

    g_node_context.chainstate = &g_chainstate;
    g_node_context.chain_selector =
        std::make_unique<dilithion::consensus::port::ChainSelectorAdapter>(g_chainstate);

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.connman = std::make_unique<CConnman>();
    g_node_context.connman->SetTestPeerManager(*g_node_context.peer_manager);

    RecordingConnmanAdapter recording_conn(*g_node_context.connman);
    dilithion::net::port::CAddrMan_v2 addrman;
    dilithion::net::port::CPeerScorer scorer;
    auto* selector = static_cast<dilithion::consensus::port::ChainSelectorAdapter*>(
        g_node_context.chain_selector.get());

    auto detached_port = std::make_unique<dilithion::net::port::CPeerManager>(
        recording_conn, addrman, scorer, *selector, s_regtestParams);
    dilithion::net::port::CPeerManager* port_raw = detached_port.get();

    g_node_context.connman->RegisterPortPeerManager(port_raw);
    g_node_context.sync_coordinator = std::make_unique<DummySyncCoordinator>();

    g_node_context.headers_manager = std::make_unique<CHeadersManager>();

    auto msg_proc = std::make_unique<CNetMessageProcessor>(*g_node_context.peer_manager);
    g_node_context.message_processor = msg_proc.get();

    msg_proc->SetHeadersHandler([](int peer_id, const std::vector<CBlockHeader>& headers) {
        if (headers.empty()) {
            return;
        }
        (void)g_node_context.headers_manager->QueueRawHeadersForProcessing(
            peer_id, std::vector<CBlockHeader>(headers));
    });

    NetProtocol::CAddress addr = MakeTestAddress();
    auto test_node = std::make_unique<CNode>(kPeerA, addr, /*inbound=*/false);
    test_node->state.store(CNode::STATE_HANDSHAKE_COMPLETE);

    assert(g_node_context.connman->DispatchPeerConnected(
        kPeerA, test_node.get(), addr, /*inbound=*/false));

    port_raw->CatchUpRegisteredLegacyPeers();

    const CBlock genesis = Genesis::CreateGenesisBlock();
    const uint256 genesis_hash = genesis.GetHash();
    const std::vector<CBlockHeader> ext = BuildVdfHeaderExtension(genesis_hash);

    const CNetMessage hdr_msg = msg_proc->CreateHeadersMessage(ext);
    assert(msg_proc->ProcessMessage(kPeerA, hdr_msg));

    assert(PollUntil(kPollTimeoutMs, [&]() {
        return g_node_context.headers_manager &&
               g_node_context.headers_manager->GetBestHeight() >= kHeaderChainLen;
    }));

    assert(port_raw->GetPeerBestKnownBlockHeight(kPeerA) < kHeaderChainLen);

    port_raw->Tick();
    assert(port_raw->GetBlocksInFlightForPeer(kPeerA) == 0);
    assert(g_chainstate.GetHeight() == 0);
    assert(recording_conn.getdata_pushes.empty());

    msg_proc->SetHeadersHandler(nullptr);
    msg_proc.reset();

    g_node_context.headers_manager.reset();
    g_node_context.connman->RegisterPortPeerManager(nullptr);
    detached_port.reset();
    g_node_context.sync_coordinator.reset();
    g_node_context.message_processor = nullptr;
    g_node_context.connman.reset();
    g_node_context.peer_manager.reset();
    g_node_context.chain_selector.reset();
    g_node_context.chainstate = nullptr;

    g_chainstate.Cleanup();
    Dilithion::g_chainParams = nullptr;
}

void test_port_peer_manager_ibd_catchup_under_usenewpeerman_v1()
{
    std::cout << "  test_port_peer_manager_ibd_catchup_under_usenewpeerman_v1..." << std::flush;
    RunPositiveMirrorPath();
    std::cout << " OK\n";
}

void test_port_peer_manager_ibd_negative_without_mirror_dynamic_cast_v1()
{
    std::cout << "  test_port_peer_manager_ibd_negative_without_mirror_dynamic_cast_v1..." << std::flush;
    RunNegativeNoMirrorDynamicCast();
    std::cout << " OK\n";
}

}  // namespace ibdl_port_mirror_test

// ============================================================================
// Test 1 — routing_connman_round_trip
// ============================================================================
void test_routing_connman_round_trip()
{
    std::cout << "  test_routing_connman_round_trip..." << std::flush;

    ThreeNodeHarness h;

    // Construct an "junk_msg" CNetMessage (empty payload, mock
    // command) and push it from fixture 0 to fixture 1. ProcessMessage
    // on fixture 1 will tick fixture 1's port_scorer with weight=1 for
    // the unknown command (UnknownMessage default weight).
    {
        std::vector<uint8_t> payload;
        ::CNetMessage msg("junk_msg", payload);
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

    // Fixture 0 sends "junk_msg" to fixture 1 AND to fixture 2,
    // each via the routing connman (mirrors a node misbehaving toward
    // both of its peers).
    for (int dest : {1, 2}) {
        std::vector<uint8_t> payload;
        ::CNetMessage msg("junk_msg", payload);
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

    // Legacy-side transport-integrity scoring assertion intentionally
    // omitted — see NodeFixture comment + PR6.5b.7-c-RT-HIGH-2 ledger
    // entry. Unit-level parity gate covers it.

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
                ::CNetMessage msg("junk_msg", payload);
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
                ::CNetMessage msg("junk_msg", payload);
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
    std::cout << "  (7-case suite — PR6.5b.7-c harness + v4.3.3 port IBD mirror)\n\n";

    try {
        test_routing_connman_round_trip();
        test_cross_node_gamma_ownership();
        test_multithreaded_three_node_concurrent_inbound();
        test_multithreaded_three_node_lifecycle_churn();
        test_mixed_full_load_three_nodes();
        ibdl_port_mirror_test::test_port_peer_manager_ibd_catchup_under_usenewpeerman_v1();
        ibdl_port_mirror_test::test_port_peer_manager_ibd_negative_without_mirror_dynamic_cast_v1();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 7 three-node integration tests passed.\n";
    return 0;
}
