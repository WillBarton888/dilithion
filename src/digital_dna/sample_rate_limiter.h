// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DIGITAL_DNA_SAMPLE_RATE_LIMITER_H
#define DILITHION_DIGITAL_DNA_SAMPLE_RATE_LIMITER_H

/**
 * DNA sample rate limiter (Phase 1 propagation fix).
 *
 * Three layers applied in order. A sample is accepted only if all three pass.
 *
 *   1. Per-peer token bucket   : 1 sample / 30s, burst 5
 *   2. Per-MIK global interval : 10 min between accepted samples for same MIK
 *   3. Per-MIK-per-peer        : 30 min between accepted samples for a (MIK, peer) pair
 *
 * Plausibility (sender-is-mapped-peer-for-MIK) is checked at the caller site,
 * not here — it needs access to `g_mik_peer_map`, which lives in the node
 * binaries.
 *
 * Thread-safe. All state is protected by a single internal mutex. Callers may
 * invoke allow() from multiple receiver threads.
 *
 * Memory: state grows with unique (peer_id) and (mik) seen. A cheap lazy-prune
 * on each allow() call drops entries that haven't been touched in 1h. No
 * explicit eviction cap — bounded by the number of peers * active MIKs, which
 * in practice is small (hundreds, not millions).
 */

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <utility>

namespace digital_dna {

class DNASampleRateLimiter {
public:
    enum class Reject {
        OK = 0,
        PEER_BUCKET,    // Per-peer token bucket exhausted
        MIK_GLOBAL,     // Per-MIK global min interval violated
        MIK_PEER,       // Per-MIK-per-peer min interval violated
    };

    // Tuning constants. Public so tests can reason about them.
    static constexpr uint64_t PEER_BUCKET_REFILL_SEC = 30;   // 1 token per 30s
    static constexpr double   PEER_BUCKET_BURST      = 5.0;  // max 5 tokens
    static constexpr uint64_t MIK_GLOBAL_MIN_SEC     = 10 * 60;
    static constexpr uint64_t MIK_PEER_MIN_SEC       = 30 * 60;
    static constexpr uint64_t PRUNE_IDLE_SEC         = 60 * 60;

    DNASampleRateLimiter() = default;

    // Returns true iff the sample is accepted. On accept, internal state is
    // updated to reflect the acceptance. On reject, state is unchanged.
    bool allow(int peer_id,
               const std::array<uint8_t, 20>& mik,
               uint64_t now_sec);

    // Same as allow() but returns the specific reject reason for diagnostics.
    Reject allow_detail(int peer_id,
                        const std::array<uint8_t, 20>& mik,
                        uint64_t now_sec);

    // For tests: reset all state.
    void clear();

    // For tests: inspect internal counters.
    size_t peer_state_size() const;
    size_t mik_global_state_size() const;
    size_t mik_peer_state_size() const;

private:
    struct TokenBucket {
        double tokens;          // current tokens
        uint64_t last_refill_sec;
    };

    // Refill the bucket to `now_sec` using PEER_BUCKET_REFILL_SEC / BURST.
    static void refill(TokenBucket& b, uint64_t now_sec);

    // Drop entries not touched in > PRUNE_IDLE_SEC.
    void prune_locked(uint64_t now_sec);

    mutable std::mutex mu_;
    std::map<int, TokenBucket> peer_buckets_;
    std::map<std::array<uint8_t, 20>, uint64_t> mik_last_accept_;
    std::map<std::pair<std::array<uint8_t, 20>, int>, uint64_t> mik_peer_last_accept_;
    uint64_t last_prune_sec_ = 0;
};

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_SAMPLE_RATE_LIMITER_H
