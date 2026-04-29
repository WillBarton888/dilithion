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

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <set>
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

    // ===== Block-download accounting (PR6.5b.4) =====
    //
    // Mark a block hash as in-flight from `peer`. Increments the per-peer
    // BlockDownloadState::n_blocks_in_flight counter and inserts the hash
    // into m_blocks_in_flight. Idempotent: re-marking the same hash from
    // the same peer is a no-op (no double-count). Lock order: takes
    // m_peers_mutex then m_blocks_in_flight_mutex (per locked partial
    // order). Peer must be present (silently ignored if disconnected).
    void MarkBlockInFlight(NodeId peer, const uint256& hash);

    // Remove a block hash from in-flight state. Decrements the per-peer
    // counter and removes the hash from m_blocks_in_flight. No-op if the
    // hash isn't tracked (does not throw, does not decrement). Same lock
    // order as MarkBlockInFlight.
    void RemoveBlockInFlight(NodeId peer, const uint256& hash);

    // Read the per-peer in-flight counter. Returns 0 for unknown peers.
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

    // HandleGetData: deserialize the inv vector and validate. Empty inv is
    // a no-op (matches upstream Bitcoin Core behavior — not misbehavior).
    // For inv entries with type=MSG_BLOCK_INV, look up the hash via
    // m_chain_selector.LookupBlockIndex(hash); unknown blocks tick scorer
    // with MisbehaviorType::UnknownMessage weight=1. Outbound block
    // payload responses are forbidden in this PR (PR6.5b.6 scope).
    // Returns true on a structurally-valid getdata; under-length throws.
    bool HandleGetData(NodeId peer, CDataStream& vRecv);

    // ===== ProcessMessage handlers (PR6.5b.2) =====
    //
    // Each handler follows the copy-state-out pattern: lock m_peers_mutex →
    // look up CPeer* → mutate fields under lock → drop lock → call out
    // (e.g., m_scorer). Under-length deserialization throws from CDataStream;
    // ProcessMessage's dispatch wraps every handler in a try/catch and routes
    // throws to the malformed-message scorer tick path.
    bool HandleVersion(NodeId peer, CDataStream& vRecv);
    bool HandleVerack(NodeId peer, CDataStream& vRecv);
    bool HandlePing(NodeId peer, CDataStream& vRecv);
    bool HandlePong(NodeId peer, CDataStream& vRecv);

    // PR6.5b.3: headers handler. Deserializes header vector, delegates to
    // CHeadersManager::ProcessHeadersWithDoSProtection via the
    // g_node_context.headers_manager raw pointer pattern, then updates
    // per-peer BlockDownloadState::n_best_known_height. SAFE: copy-state-out
    // — every callout to m_scorer / g_node_context.headers_manager happens
    // outside m_peers_mutex (and outside m_sync_state_mutex).
    bool HandleHeaders(NodeId peer, CDataStream& vRecv);

    // PR6.5b.3: headers-sync helpers. Each helper performs the full
    // copy-state-out pattern (read peer state under m_peers_mutex, drop;
    // mutate m_sync_state_mutex data, drop; perform any
    // g_node_context.headers_manager callout outside both locks).
    //
    // *_Locked suffix is a misnomer that mirrors the upstream IBD
    // coordinator's helper naming (SelectHeadersSyncPeer /
    // CheckHeadersSyncProgress / SwitchHeadersSyncPeer). They run under
    // the m_sync_state_mutex they manage internally — the caller MUST
    // NOT already hold m_sync_state_mutex.
    void SelectHeadersSyncPeerLocked();
    bool CheckHeadersSyncProgressLocked();
    void SwitchHeadersSyncPeerLocked(bool penalize);

    // PR6.5b.5: sync-state hysteresis update. Reads
    // headers_manager->GetBestHeight() + m_chain_selector.GetActiveHeight()
    // OUTSIDE m_sync_state_mutex, then flips m_synced under hysteresis
    // rules (SYNC_TOLERANCE_BLOCKS / UNSYNC_THRESHOLD_BLOCKS). MUST NOT
    // be called with m_sync_state_mutex held — the *_Locked suffix is
    // the same naming-misnomer convention used by PR6.5b.3 helpers.
    void UpdateSyncStateLocked();

    // PR6.5b.5: walk m_blocks_in_flight, snapshot stale (hash, peer_id)
    // pairs under m_blocks_in_flight_mutex briefly, drop, then call
    // RemoveBlockInFlight(peer, hash) for each (which takes its own
    // locks). NO scorer dispatch, NO disconnect — misbehavior on stall
    // is PR6.5b.6.
    void RetryStaleBlocksLocked();

    // PR6.5b.5: any-peer handshake-complete check. Walks m_peers under
    // m_peers_mutex briefly; returns true iff any CPeer::m_handshake_complete
    // is true. Replaces the legacy
    // m_node_context.peer_manager->HasCompletedHandshakes() callout from
    // CIbdCoordinator::UpdateState:389-390 with a port-side equivalent.
    bool HasCompletedHandshakeWithAnyPeer() const;

    // ===== Lock-order discipline (v1.5 §2.1.1 rule 5; Option B) =====
    //
    // Partial order:  connman_peer_lock < m_peers_mutex
    //                 < m_sync_state_mutex
    //                 < m_blocks_in_flight_mutex < cs_main
    //
    // The new m_sync_state_mutex slots BETWEEN m_peers_mutex and
    // m_blocks_in_flight_mutex (PR6.5b.3, HIGH-risk lock-order discipline).
    //
    // Hard rules:
    //   * No callout under m_peers_mutex OR m_sync_state_mutex. Copy state
    //     out, drop lock, then call out (m_scorer, m_connman, m_chain_selector,
    //     g_node_context.headers_manager).
    //   * Mutexes are std::mutex (NOT std::recursive_mutex). Re-entry from
    //     a callback is forbidden — that's the AB/BA route Option B's CI
    //     gates close.
    //   * Inbound chain.cpp callbacks fire SYNCHRONOUSLY under cs_main
    //     (Option B; not Option A's queue dispatch). PeerManager
    //     handlers MUST be invokable under cs_main.

    std::map<NodeId, std::unique_ptr<CPeer>> m_peers;
    mutable std::mutex m_peers_mutex;

    // PR6.5b.3: headers-sync state. CPeerManager is authoritative for
    // "is this peer the chosen sync-peer." (CHeadersManager remains
    // authoritative for "have I started syncing from this peer" —
    // SSOT split per decomposition.)
    NodeId m_headers_sync_peer{-1};                                  // current sync peer
    int m_headers_sync_last_height{0};                               // height at last progress check
    uint64_t m_headers_sync_last_processed{0};                       // processed count at last progress check
    std::chrono::steady_clock::time_point m_headers_sync_timeout{};  // when sync peer is considered stalled
    int m_headers_sync_peer_consecutive_stalls{0};                   // consecutive stalls for current peer
    std::set<NodeId> m_headers_bad_peers;                            // peers that repeatedly stalled
    mutable std::mutex m_sync_state_mutex;

    // PR6.5b.3 timeout / stall constants. Mirror upstream
    // CIbdCoordinator::HEADERS_SYNC_TIMEOUT_BASE_SECS /
    // HEADERS_SYNC_TIMEOUT_PER_HEADER_MS / MAX_HEADERS_CONSECUTIVE_STALLS.
    static constexpr int HEADERS_SYNC_TIMEOUT_BASE_SECS = 120;
    static constexpr int HEADERS_SYNC_TIMEOUT_PER_HEADER_MS = 1;
    static constexpr int MAX_HEADERS_CONSECUTIVE_STALLS = 3;

    // PR6.5b.5 hysteresis + stall-timeout constants (SSOT — private to
    // CPeerManager; mirrors CIbdCoordinator's private constants in
    // ibd_coordinator.h:203-204 and the literal `(blocks_behind <= 20)
    // ? 15 : 60` selector at ibd_coordinator.cpp:2174).
    static constexpr int SYNC_TOLERANCE_BLOCKS = 2;
    static constexpr int UNSYNC_THRESHOLD_BLOCKS = 10;
    static constexpr int BLOCK_TIMEOUT_NEAR_TIP_SECS = 15;
    static constexpr int BLOCK_TIMEOUT_BULK_SECS = 60;
    static constexpr int BLOCKS_NEAR_TIP_THRESHOLD = 20;

    // PR6.5b.5 sync state. std::atomic<bool> mirrors
    // CIbdCoordinator::m_synced idiom (ibd_coordinator.h). NO mutex —
    // single bool, atomic acquire/release. Initial value matches legacy:
    // start NOT synced (so IsInitialBlockDownload() == true at construction).
    std::atomic<bool> m_synced{false};

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
