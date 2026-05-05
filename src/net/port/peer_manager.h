// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b — PeerManager skeleton (per v1.5 plan §2.1).
//
// Ports upstream Bitcoin Core v28 net_processing.cpp PeerManager pattern,
// adapted to Dilithion's idiom. Implements ISyncCoordinator (PR6.5a
// adapter surface) so call sites that previously used IBDCoordinator
// can flip to PeerManager via the --usenewpeerman=1 flag.
//
// Status v1.5 / overnight handoff: SKELETON ONLY. The class declaration
// is locked; method bodies are stubbed. Full implementation is the body
// work of PR6.5b in subsequent sessions.
//
// Namespace: dilithion::net::port (DISTINCT from the v4-era ::CPeerManager
// in src/net/peers.h).

#ifndef DILITHION_NET_PORT_PEER_MANAGER_H
#define DILITHION_NET_PORT_PEER_MANAGER_H

#include <core/chainparams.h>
#include <net/iconnection_manager.h>
#include <net/port/sync_coordinator.h>

#include <atomic>
#include <chrono>
#include <vector>

class CBlock;
class CBlockHeader;
class CDataStream;

namespace dilithion {

namespace consensus { class IChainSelector; }

namespace net {

class IConnectionManager;
class IAddressManager;
class IPeerScorer;

namespace port {

// Block-download bookkeeping (one entry per in-flight block hash).
struct BlockDownloadInfo {
    NodeId peer_id;
    int64_t requested_at_unix_sec;
    int height;
};

// Per-peer info struct returned by GetPeerInfo() (matches the legacy
// PeerInfo shape used by RPC layer).
struct PeerInfo {
    NodeId id;
    int version;
    uint64_t services;
    int64_t time_connected;
    bool is_sync_peer;
};

// Phase 6 PR6.5b PeerManager. Implements ISyncCoordinator so the
// --usenewpeerman=1 flag swaps this in transparently for IBDCoordinator
// at the 37 call sites migrated in PR6.5a.
class CPeerManager : public ::dilithion::net::port::ISyncCoordinator {
public:
    // Construction wires consumed interfaces. None are held by smart
    // pointer here; PeerManager does not own them.
    //
    // Lifetime contract: every reference passed in MUST outlive this
    // CPeerManager instance.
    CPeerManager(::dilithion::net::IConnectionManager& connman,
                 ::dilithion::net::IAddressManager& addrman,
                 ::dilithion::net::IPeerScorer& scorer,
                 ::dilithion::consensus::IChainSelector& chain_selector,
                 const ::Dilithion::ChainParams& chainparams);

    ~CPeerManager() override;

    // ===== ISyncCoordinator overrides (matches §1.5 conformance table) =====
    bool IsInitialBlockDownload() const override;
    bool IsSynced() const override;
    int GetHeadersSyncPeer() const override;
    void OnOrphanBlockReceived() override;
    void OnBlockConnected() override;
    void Tick() override;

    // ===== PeerManager-specific API =====

    // Per-message dispatch. Called from connman's ThreadMessageHandler.
    // Returns true if the message was handled successfully.
    bool ProcessMessage(NodeId peer, const std::string& strCommand,
                        CDataStream& vRecv);

    // Per-peer maintenance cycle. Called once per ThreadMessageHandler iter.
    void SendMessages(NodeId peer);

    // Peer info for RPC.
    int GetPeerCount() const;
    std::vector<PeerInfo> GetPeerInfo() const;

    // Connection lifecycle (called by connman on connect/disconnect).
    void OnPeerConnected(NodeId peer);
    void OnPeerDisconnected(NodeId peer);

    // Block-download accounting hooks retained as no-ops while HandleBlock
    // still calls them; Block 6 removes this surface with HandleBlock.
    void MarkBlockInFlight(NodeId peer, const uint256& hash);
    void RemoveBlockInFlight(NodeId peer, const uint256& hash);
    int GetBlocksInFlightForPeer(NodeId peer) const;

private:
    // ===== Block-download handlers (PR6.5b.4) =====
    //
    // HandleBlock: deserialize CBlock from vRecv, look up the block hash,
    // call RemoveBlockInFlight(peer, hash) if tracked, then call
    // m_chain_selector.ProcessNewBlock with NO PeerManager locks held.
    // Always returns true on a structurally-valid block payload (handler
    // success means "we delegated"; chain_selector reports its own
    // verdict via existing legacy paths). Under-length read throws and
    // is caught by ProcessMessage's try/catch (UnknownMessage weight=1).
    bool HandleBlock(NodeId peer, CDataStream& vRecv);

    // HandleGetData declaration removed in v4.3.4 cut Block 2 — was never reached
    // in production (Layer-3 H4 + audit gap-list G04).

    // Counter incremented from
    // OnOrphanBlockReceived() (parameterless per ISyncCoordinator §1.5).
    std::atomic<int> m_consecutive_orphan_blocks{0};

    // Updated from OnBlockConnected; read by telemetry/RPC surfaces.
    std::atomic<int64_t> m_last_block_connected_ticks{0};

    // Sync state atomically recomputed from chain/header heights.
    std::atomic<bool> m_synced{false};

    // Held interfaces (non-owning).
    ::dilithion::net::IConnectionManager& m_connman;
    ::dilithion::net::IAddressManager& m_addrman;
    ::dilithion::net::IPeerScorer& m_scorer;
    ::dilithion::consensus::IChainSelector& m_chain_selector;
    const ::Dilithion::ChainParams& m_chainparams;

    // PR6.5b.test-hardening — injection-seam fields. PRIVATE, friend-gated
    // (only ::SyncStateFixture may write). Production-default sentinels
    // route to the real sources via Now() / GetHeaderHeightForSync() /
    // GetChainHeightForSync(). NEVER set from production code; NEVER
    // exposed via wire / RPC / config / public API.
    int64_t m_test_now_override = 0;
    int64_t m_test_header_height_override = -1;
    int64_t m_test_chain_height_override = -1;
};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_PEER_MANAGER_H
