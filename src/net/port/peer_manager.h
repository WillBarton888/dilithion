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
#include <net/port/peer.h>
#include <net/port/sync_coordinator.h>

#include <map>
#include <memory>
#include <mutex>
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

    // Per-peer maintenance cycle. Sync rotation, stall detection,
    // in-flight cleanup. Called once per ThreadMessageHandler iter.
    void SendMessages(NodeId peer);

    // Block-download dispatch. Called from Tick() when in IBD.
    void RequestNextBlocks();

    // Peer info for RPC.
    int GetPeerCount() const;
    std::vector<PeerInfo> GetPeerInfo() const;

    // Connection lifecycle (called by connman on connect/disconnect).
    void OnPeerConnected(NodeId peer);
    void OnPeerDisconnected(NodeId peer);

private:
    // ===== Lock-order discipline (v1.5 §2.1.1 rule 5; Option B) =====
    //
    // Partial order:  connman_peer_lock < m_peers_mutex
    //                 < m_blocks_in_flight_mutex < cs_main
    //
    // Hard rules:
    //   * No callout under m_peers_mutex. Copy state out, drop lock,
    //     then call out.
    //   * m_peers_mutex is std::mutex (NOT std::recursive_mutex).
    //     Re-entry from a callback is forbidden — that's the AB/BA
    //     route Option B's CI gates close.
    //   * Inbound chain.cpp callbacks fire SYNCHRONOUSLY under cs_main
    //     (Option B; not Option A's queue dispatch). PeerManager
    //     handlers MUST be invokable under cs_main.

    std::map<NodeId, std::unique_ptr<CPeer>> m_peers;
    mutable std::mutex m_peers_mutex;

    std::map<uint256, BlockDownloadInfo> m_blocks_in_flight;
    mutable std::mutex m_blocks_in_flight_mutex;

    // Held interfaces (non-owning).
    ::dilithion::net::IConnectionManager& m_connman;
    ::dilithion::net::IAddressManager& m_addrman;
    ::dilithion::net::IPeerScorer& m_scorer;
    ::dilithion::consensus::IChainSelector& m_chain_selector;
    const ::Dilithion::ChainParams& m_chainparams;
};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_PEER_MANAGER_H
