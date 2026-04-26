// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 — CPeerScorer implementation.
//
// Implements the FROZEN IPeerScorer interface (src/net/ipeer_scorer.h).
// Algorithm is Bitcoin Core's legacy v25.x numeric-scoring shape: per-peer
// cumulative weight, ban-on-threshold-cross. Current upstream Bitcoin Core
// migrated to a binary "should discourage" flag (net_processing.cpp:1939);
// Dilithion retains numeric scoring for finer-grained policy + operator
// visibility. Documented in detail at the top of ipeer_scorer.h.
//
// Phase 2 plan §10 decisions encoded here:
//   * Q1=C — score store is an in-memory map; no persistence path
//   * Q2=A — Misbehaving returns bool (threshold crossed); the FORWARDER in
//            CPeerManager calls CBanManager::Ban. CPeerScorer has no
//            CBanManager dependency.

#include <net/port/peer_scorer.h>
#include <net/port/misbehavior_policy.h>
#include <net/peers.h>             // CPeerManager::MAX_TOTAL_CONNECTIONS for assertion bound

#include <algorithm>
#include <cassert>

namespace dilithion::net::port {

// ============================================================================
// Construction / destruction
// ============================================================================

CPeerScorer::CPeerScorer() = default;
CPeerScorer::~CPeerScorer() = default;

// ============================================================================
// Public IPeerScorer API
// ============================================================================

bool CPeerScorer::Misbehaving(::dilithion::net::NodeId peer,
                              ::dilithion::net::MisbehaviorType type,
                              const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const int weight = DefaultWeight(type);
    return AddScoreLocked(peer, weight, reason);
}

bool CPeerScorer::Misbehaving(::dilithion::net::NodeId peer,
                              int weight,
                              const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return AddScoreLocked(peer, weight, reason);
}

int CPeerScorer::GetScore(::dilithion::net::NodeId peer) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_scores.find(peer);
    return (it == m_scores.end()) ? 0 : it->second;
}

void CPeerScorer::ResetScore(::dilithion::net::NodeId peer)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // Erase rather than zero — the slot is re-claimable. This is the
    // expected callpath from CPeerManager::RemovePeer when a peer
    // disconnects; bounded score-map size depends on this erasure.
    m_scores.erase(peer);
}

void CPeerScorer::SetBanThreshold(int threshold)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ban_threshold = threshold;
}

int CPeerScorer::GetBanThreshold() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_ban_threshold;
}

// ============================================================================
// Helpers
// ============================================================================

// Decay every tracked score by 1, floored at 0. Mirrors the existing
// CPeerManager::DecayMisbehaviorScores behaviour at peers.cpp:486-490
// (which is itself a deliberate divergence from upstream — Bitcoin Core
// does not decay; we do, called every 30s).
//
// Zero-score entries are NOT erased here. ResetScore is the explicit
// cleanup path; entries naturally shrink when peers disconnect via
// CPeerManager::RemovePeer → CPeerScorer::ResetScore. Auto-erasing on zero
// would race against in-flight Misbehaving calls for the same NodeId.
void CPeerScorer::DecayAll()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [peer, score] : m_scores) {
        score = std::max(0, score - 1);
    }
}

size_t CPeerScorer::GetScoreMapSizeForTest() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_scores.size();
}

// ============================================================================
// Private — caller holds m_mutex
// ============================================================================

bool CPeerScorer::AddScoreLocked(::dilithion::net::NodeId peer,
                                 int weight,
                                 const std::string& /*reason*/)
{
    // Zero or negative weight is a no-op per upstream pattern (callers can
    // pass 0 to "report misbehavior without a quantifiable penalty").
    if (weight <= 0) return false;

    // Sanity assertion (debug-only): catch unbounded growth from a
    // forgotten ResetScore on a disconnect path. Bound is 10x the
    // configured peer cap. Cursor Phase 2 review Q9 (2026-04-26): named
    // constant (not magic number) so the bound stays anchored if
    // MAX_TOTAL_CONNECTIONS ever moves.
    constexpr size_t kScoreMapMaxBound = 10 * CPeerManager::MAX_TOTAL_CONNECTIONS;
    assert(m_scores.size() <= kScoreMapMaxBound &&
           "CPeerScorer score map leak — ResetScore likely missing from a "
           "disconnect path");

    int& score = m_scores[peer];  // creates entry if missing (default 0)
    score += weight;

    // Clamp at ban threshold for the bool return — exact-or-over.
    return score >= m_ban_threshold;
}

}  // namespace dilithion::net::port
