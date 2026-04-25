// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 4 interface contract. Selects the sync peer + block-relay targets
// from a candidate set of connected peers. Replaces the broken
// IBDCoordinator::SelectHeadersSyncPeer logic where a single bad sync peer
// could pin the node forever.

#ifndef DILITHION_NET_IPEER_SELECTOR_H
#define DILITHION_NET_IPEER_SELECTOR_H

#include <cstdint>
#include <chrono>
#include <optional>
#include <vector>

namespace dilithion::net {

using NodeId = int;

// A candidate peer for selection. Bigger struct than just NodeId because
// the selector needs to make informed choices (height, last-progress time,
// connection class, score).
struct PeerCandidate {
    NodeId node_id;
    int64_t best_known_height;
    int64_t starting_height;
    bool is_outbound;
    bool is_manual;                                // --addnode persistent
    int misbehavior_score;
    std::chrono::steady_clock::time_point last_block_received;
    std::chrono::steady_clock::time_point last_header_received;
    std::chrono::steady_clock::time_point connected_at;
    int blocks_in_flight;
};

// Reason a peer was de-selected, used to decide whether to penalize them
// in the AddrMan quality model. (v4.0.22 Patch F gated penalty by reason —
// upstream PeerManager does this properly via a typed enum.)
enum class DeselectReason {
    Disconnected,            // Peer dropped; not a fault
    StalledNoBlocks,         // Selected but never delivered blocks
    StalledNoHeaders,        // Selected but never delivered headers
    OutOfSyncHeight,         // Peer's claimed height is below our tip
    PoolExhausted,           // No better candidate; reset pool
    BadFork,                 // Peer is on a chain that fails validation
    Replaced,                // Just rotated; not a fault
};

class IPeerSelector {
public:
    virtual ~IPeerSelector() = default;

    // Pick the best peer for HEADERS sync from candidates. Bias:
    //   1. Highest-known-height (must exceed our tip)
    //   2. Outbound > Inbound
    //   3. Manual > Discovered
    //   4. Lowest misbehavior_score
    //   5. Most-recent successful block delivery
    // Excludes peers in m_bad_set unless pool exhausted (then clears bad set).
    // Returns nullopt if no candidate is acceptable.
    virtual std::optional<NodeId> SelectHeadersSyncPeer(
        const std::vector<PeerCandidate>& candidates) = 0;

    // Pick a peer for BLOCK fetch (separate from headers). Same bias but
    // also avoids peers at MAX_BLOCKS_IN_TRANSIT_PER_PEER.
    virtual std::optional<NodeId> SelectBlockFetchPeer(
        const std::vector<PeerCandidate>& candidates) = 0;

    // Notify selector that a peer was de-selected and why. Selector may
    // add to bad_set, update score, or ignore depending on reason.
    virtual void NotifyDeselected(NodeId peer, DeselectReason reason) = 0;

    // Test if peer is currently in the bad set. Public for diagnostic RPC.
    virtual bool IsBadPeer(NodeId peer) const = 0;

    // Force-clear the bad set (operator override / pool-exhausted recovery).
    virtual void ClearBadSet() = 0;

    // Diagnostics — expose selector state for getpeerinfo.
    virtual size_t BadSetSize() const = 0;
};

}  // namespace dilithion::net

#endif  // DILITHION_NET_IPEER_SELECTOR_H
