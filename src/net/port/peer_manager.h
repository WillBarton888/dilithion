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

class CBlock;
class CBlockHeader;
namespace dilithion {

namespace consensus { class IChainSelector; }

namespace net {

namespace port {

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
    CPeerManager(::dilithion::consensus::IChainSelector& chain_selector,
                 const ::Dilithion::ChainParams& chainparams);

    ~CPeerManager() override;

    // ===== ISyncCoordinator overrides (matches §1.5 conformance table) =====
    bool IsInitialBlockDownload() const override;
    bool IsSynced() const override;
    int GetHeadersSyncPeer() const override;
    void OnOrphanBlockReceived() override;
    void OnBlockConnected() override;
    void Tick() override;

    // Connection lifecycle hooks are retained as no-op implementations while
    // connman still calls DispatchPeerConnected/Disconnected wrappers.
    void OnPeerConnected(NodeId peer);
    void OnPeerDisconnected(NodeId peer);

    // Counter incremented from
    // OnOrphanBlockReceived() (parameterless per ISyncCoordinator §1.5).
    std::atomic<int> m_consecutive_orphan_blocks{0};

    // Updated from OnBlockConnected; read by telemetry/RPC surfaces.
    std::atomic<int64_t> m_last_block_connected_ticks{0};

    // Sync state atomically recomputed from chain/header heights.
    std::atomic<bool> m_synced{false};

private:
    ::dilithion::consensus::IChainSelector& m_chain_selector;
    const ::Dilithion::ChainParams& m_chainparams;
};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_PEER_MANAGER_H
