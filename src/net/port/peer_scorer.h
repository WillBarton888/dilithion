// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 of the Bitcoin Core peer/IBD/chain-selection port.
// Implements the FROZEN IPeerScorer interface (src/net/ipeer_scorer.h).
//
// Algorithm: Bitcoin Core's legacy v25.x numeric-scoring shape — accumulate
// per-peer points, ban when threshold (default 100) crossed. Current upstream
// Bitcoin Core uses a binary "should discourage" flag instead; Dilithion
// retains numeric scoring for finer-grained policy + operator visibility.
// This is a deliberate divergence; see comment block on top of peer_scorer.cpp.
//
// C++ idiom Dilithion-native (carrying over Phase 1's PORT PRINCIPLE):
//   * std::mutex (no upstream EXCLUSIVE_LOCKS_REQUIRED annotations)
//   * std::map<NodeId, int> for the score store (NodeIds are dense small ints
//     bounded by MAX_TOTAL_CONNECTIONS; map is fine, no need for unordered)
//   * int64_t Unix seconds (no NodeSeconds wrapper)
//
// Phase 2 scope decisions (per port_phase_2_implementation_plan.md §10):
//   * Q1=C — transient-only score store, no persistence
//   * Q2=A — caller (CPeerManager forwarder) calls CBanManager::Ban; this
//            class only reports threshold cross
//   * Q5=C — MaybePunishNodeForBlock/Tx/Headers wrappers deferred to Phase 3

#ifndef DILITHION_NET_PORT_PEER_SCORER_H
#define DILITHION_NET_PORT_PEER_SCORER_H

#include <net/ipeer_scorer.h>
#include <cstddef>
#include <map>
#include <mutex>
#include <string>

namespace dilithion::net::port {

class CPeerScorer final : public ::dilithion::net::IPeerScorer {
public:
    CPeerScorer();
    ~CPeerScorer() override;

    // Disable copy / move — single instance per node.
    CPeerScorer(const CPeerScorer&) = delete;
    CPeerScorer& operator=(const CPeerScorer&) = delete;

    // ---- IPeerScorer interface ----

    bool Misbehaving(::dilithion::net::NodeId peer,
                     ::dilithion::net::MisbehaviorType type,
                     const std::string& reason = "") override;

    bool Misbehaving(::dilithion::net::NodeId peer,
                     int weight,
                     const std::string& reason = "") override;

    int  GetScore(::dilithion::net::NodeId peer) const override;

    void ResetScore(::dilithion::net::NodeId peer) override;

    void SetBanThreshold(int threshold) override;
    int  GetBanThreshold() const override;

    // ---- Configuration / lifecycle helpers (called by CPeerManager) ----

    // Decay every tracked score by 1, floored at 0. Designed to be called on
    // CPeerManager's existing 30-second decay tick. Drift from upstream:
    // Bitcoin Core does NOT decay; it just resets on disconnect. Dilithion's
    // decay matches the existing CPeer.misbehavior_score behaviour pre-Phase 2,
    // so the cutover is behaviour-equivalent to operators.
    void DecayAll();

    // ---- Test diagnostics ----

    // Number of NodeIds currently tracked. Used by the slot-reclamation
    // regression test (test_reset_score_clears_map_entry) to verify
    // ResetScore actually erases the entry rather than zeroing it. Naming
    // matches Phase 1 convention: *ForTest() suffix, public, scoped.
    size_t GetScoreMapSizeForTest() const;

private:
    mutable std::mutex m_mutex;

    // NodeId → cumulative score. Entries created lazily on first Misbehaving
    // call; removed on ResetScore. Bounded in practice by MAX_TOTAL_CONNECTIONS
    // (125) — but no static cap enforced; debug-mode assertion in the
    // implementation catches drift if the map exceeds 10x that bound.
    std::map<::dilithion::net::NodeId, int> m_scores;

    // Default 100; mutable via SetBanThreshold. Mirrors CPeerManager::BAN_THRESHOLD.
    int m_ban_threshold = 100;

    // Internal: add `weight` to peer's score and check threshold.
    // Caller must hold m_mutex. Returns true iff score >= m_ban_threshold
    // after this addition. Logs at WARN on threshold cross.
    bool AddScoreLocked(::dilithion::net::NodeId peer,
                        int weight,
                        const std::string& reason);
};

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_PEER_SCORER_H
