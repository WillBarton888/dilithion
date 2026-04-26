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
    int64_t nTimeConnected = 0;

    // Block-flow state.
    BlockDownloadState m_block_download;
    std::set<uint256> m_blocks_in_flight;
    std::chrono::steady_clock::time_point m_last_block_announcement{};

    // Sync-peer rotation (only one peer is the sync-peer at a time).
    bool m_is_block_relay_only = false;
    bool m_is_chosen_sync_peer = false;

    // Dilithion-native: DNA envelope handling (Phase 1.5 SMP1).
    bool m_dna_envelope_seen = false;

    CPeer() = default;
    explicit CPeer(NodeId nodeId) : id(nodeId) {}
};

}  // namespace port
}  // namespace net
}  // namespace dilithion

#endif  // DILITHION_NET_PORT_PEER_H
