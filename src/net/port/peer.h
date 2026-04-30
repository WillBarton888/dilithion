// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b — Per-peer state struct (skeleton).
//
// Mirrors upstream Bitcoin Core v28 net_processing.cpp's `Peer` struct
// adapted to Dilithion's idiom:
//   * std::mutex (not annotated Mutex)
//   * std::map (not unordered_map)
//   * int64_t Unix seconds (not std::chrono::time_point in serialized state)
//   * No PIMPL
//   * Dilithion-native fields (DNA envelope state, MIK pubkey cache ref)
//
// Status v1.5 / overnight handoff: SKELETON ONLY. Member declarations
// are the contract; method bodies + initialization order are PR6.5b body
// work to be completed in subsequent sessions.

#ifndef DILITHION_NET_PORT_PEER_H
#define DILITHION_NET_PORT_PEER_H

#include <chrono>
#include <cstdint>
#include <set>
#include <uint256.h>

namespace dilithion {
namespace net {
namespace port {

// Phase 6 PR6.5b (v1.5 fix-up 2026-04-27 per dual-validation): aligned to
// project-wide NodeId convention (int — see block_tracker.h, headerssync.h,
// iconnection_manager.h, etc.). Upstream Bitcoin Core uses int64_t but
// Dilithion standardized on int; SSOT discipline says match existing.
using NodeId = int;

// Per-peer block-download state. Replaces the global m_last_hang_cause /
// HangCause enum from CIbdCoordinator. Each connected peer has one
// instance; lifetime = peer connection.
struct BlockDownloadState {
    int n_blocks_in_flight = 0;
    int64_t n_starting_height = -1;
    int64_t n_best_known_height = -1;
    int64_t n_last_block_announcement = 0;
    int64_t n_last_block_arrival = 0;
    int n_blocks_failed_to_arrive = 0;
};

// Per-peer state. Mirrors upstream's `Peer` struct.
//
// Construction: CPeerManager owns CPeer instances via std::unique_ptr<CPeer>
// keyed by NodeId in m_peers. Lifetime = OnPeerConnected → OnPeerDisconnected.
//
// Lock-order discipline (per v1.5 §2.1.1 rule 5): handlers MUST be
// invokable under cs_main. Use copy-state-out-then-callout when
// reading/writing CPeer fields from a chain.cpp callback path.
struct CPeer {
    NodeId id = -1;

    // Connection metadata (filled by OnPeerConnected from connman).
    int nVersion = 0;
    uint64_t nServices = 0;

    // Local connect-time (PR6.5b.fixups-semantic, finding PR6.5b.2-SEC-MD-2).
    // Set by OnPeerConnected from GetTime() — matches the original documented
    // semantics of the legacy `nTimeConnected` field. Trusted local-clock value.
    int64_t nTimeConnectedLocal = 0;

    // Peer-claimed wire timestamp (PR6.5b.fixups-semantic, finding
    // PR6.5b.2-SEC-MD-2). Attacker-controlled int64 from the VERSION message.
    // Bounds-checked in HandleVersion against `now ± Consensus::MAX_FUTURE_BLOCK_TIME`
    // before being stored; out-of-range values trigger UnknownMessage misbehavior
    // and are NOT written to this field. Never use as a trusted clock source.
    int64_t m_peer_claimed_time = 0;

    // Duplicate-version sentinel (PR6.5b.fixups-mechanical, finding
    // PR6.5b.2-SEC-MD-1). The legacy `nVersion != 0` test misclassified a
    // peer that legitimately sent `version=0` on the first message: the
    // duplicate-version check would never fire on a second VERSION because
    // nVersion still tested as zero. This bool is set true on the first
    // VERSION (regardless of read_version's value) and tested in
    // HandleVersion to dispatch DuplicateVersion misbehavior on the second.
    bool m_version_received = false;

    // Block-flow state.
    BlockDownloadState m_block_download;
    std::set<uint256> m_blocks_in_flight;
    std::chrono::steady_clock::time_point m_last_block_announcement{};

    // Sync-peer rotation (only one peer is the sync-peer at a time).
    bool m_is_block_relay_only = false;
    bool m_is_chosen_sync_peer = false;

    // Handshake state (set by version/verack handlers in PR6.5b.2).
    // m_handshake_complete is set by the verack handler; mirrors upstream's
    // "fSuccessfullyConnected" flag.
    bool m_handshake_complete = false;

    // Ping/pong tracking (set by ping/pong handlers in PR6.5b.2).
    // m_last_ping_nonce_recvd holds the nonce from the last received ping so
    // PR6.5b.6 SendMessages can produce the pong reply. m_pong_expected /
    // m_pong_expected_nonce track an outstanding outbound ping (set by
    // PR6.5b.6's ping issuance; cleared by the pong handler on a matching
    // nonce). With a wrong/unexpected nonce, the pong handler ticks scorer.
    uint64_t m_last_ping_nonce_recvd = 0;
    bool     m_pong_expected = false;
    uint64_t m_pong_expected_nonce = 0;

    // Dilithion-native: DNA envelope handling (Phase 1.5 SMP1).
    bool m_dna_envelope_seen = false;

    CPeer() = default;
    explicit CPeer(NodeId nodeId) : id(nodeId) {}
};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_PEER_H
