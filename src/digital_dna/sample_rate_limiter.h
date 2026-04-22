// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DIGITAL_DNA_SAMPLE_RATE_LIMITER_H
#define DILITHION_DIGITAL_DNA_SAMPLE_RATE_LIMITER_H

/**
 * DNA sample rate limiter (Phase 1 propagation fix + Phase 1.5 split pipeline).
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
 * Two usage modes:
 *   A) Atomic  (Phase 1 / 1.1 callers): `allow()` / `allow_detail()` check and
 *      consume all three layers in one shot. State is only mutated on accept.
 *   B) Staged  (Phase 1.5 signed pipeline): layer 1 is consumed BEFORE the
 *      expensive signature verify via `consume_peer_bucket()`, and layers 2+3
 *      are split into a check-without-commit (`check_mik_limits`) and a commit
 *      step (`commit_mik_limits`) so receiver stages 4+5 can reject-without-
 *      commit if the signature fails or the sample is a replay.
 *
 * Phase 1.5 also colocates the replay FIFO for signed samples here (rather
 * than adding a third concurrency-protected class). The key is
 * `SHA3-256(mik || ts_le || nonce_le)` and entries expire after 10 min.
 *
 * Thread-safe. All state is protected by a single internal mutex. Callers may
 * invoke any public method from multiple receiver threads.
 *
 * Memory: state grows with unique (peer_id) and (mik) seen. A cheap lazy-prune
 * on each call drops entries that haven't been touched in 1h. Replay FIFO is
 * bounded by the 10-min TTL (hundreds of entries at typical traffic).
 */

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>
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
    static constexpr uint64_t REPLAY_TTL_SEC         = 10 * 60;

    DNASampleRateLimiter() = default;

    // ---- Atomic (Phase 1/1.1) --------------------------------------------

    // Returns true iff the sample is accepted. On accept, internal state is
    // updated to reflect the acceptance. On reject, state is unchanged.
    bool allow(int peer_id,
               const std::array<uint8_t, 20>& mik,
               uint64_t now_sec);

    // Same as allow() but returns the specific reject reason for diagnostics.
    Reject allow_detail(int peer_id,
                        const std::array<uint8_t, 20>& mik,
                        uint64_t now_sec);

    // ---- Staged (Phase 1.5) ----------------------------------------------

    // Consume one token from the peer bucket. Used at receive pipeline stage 2,
    // before signature verify, to cap verification work per peer regardless of
    // MIK spread. Returns true iff a token was consumed. The bucket is the
    // same state that `allow()` uses; a token spent here counts toward the
    // per-peer burst limit.
    bool consume_peer_bucket(int peer_id, uint64_t now_sec);

    // Check MIK-global and MIK-per-peer intervals without mutating. Returns
    // true iff both intervals would allow a new acceptance right now. Callers
    // run this at stage 5 (after verify + skew + replay) and then call
    // `commit_mik_limits()` before `append_sample`.
    bool check_mik_limits(int peer_id,
                          const std::array<uint8_t, 20>& mik,
                          uint64_t now_sec);

    // Commit MIK-global and MIK-per-peer acceptance records. Must be called
    // only after `check_mik_limits()` returned true and stages 4/5 passed.
    void commit_mik_limits(int peer_id,
                           const std::array<uint8_t, 20>& mik,
                           uint64_t now_sec);

    // Replay cache — lookup without mutation. Returns true iff
    // SHA3-256(mik || ts || nonce) is already in the 10-min FIFO.
    bool replay_seen(const std::array<uint8_t, 20>& mik,
                     uint64_t ts,
                     uint64_t nonce);

    // Replay cache — record the (mik, ts, nonce) triple. Should be called
    // only once the sample is fully accepted (stage 6).
    void replay_record(const std::array<uint8_t, 20>& mik,
                       uint64_t ts,
                       uint64_t nonce,
                       uint64_t now_sec);

    // ---- Test helpers ----------------------------------------------------

    // For tests: reset all state.
    void clear();

    // For tests: inspect internal counters.
    size_t peer_state_size() const;
    size_t mik_global_state_size() const;
    size_t mik_peer_state_size() const;
    size_t replay_cache_size() const;

private:
    struct TokenBucket {
        double tokens;          // current tokens
        uint64_t last_refill_sec;
    };

    // Refill the bucket to `now_sec` using PEER_BUCKET_REFILL_SEC / BURST.
    static void refill(TokenBucket& b, uint64_t now_sec);

    // Ensure `peer_buckets_[peer_id]` exists and is up-to-date.
    // Returns a reference to the bucket (must be under lock).
    TokenBucket& get_bucket_locked(int peer_id, uint64_t now_sec);

    // Check/commit MIK layers — under lock.
    bool check_mik_locked(int peer_id,
                          const std::array<uint8_t, 20>& mik,
                          uint64_t now_sec) const;
    void commit_mik_locked(int peer_id,
                           const std::array<uint8_t, 20>& mik,
                           uint64_t now_sec);

    // Compute the replay key = SHA3-256(mik || ts_le || nonce_le).
    static std::array<uint8_t, 32> replay_key(
        const std::array<uint8_t, 20>& mik,
        uint64_t ts,
        uint64_t nonce);

    // Drop entries not touched in > PRUNE_IDLE_SEC (rate-limit layers).
    void prune_locked(uint64_t now_sec);

    // Drop replay entries whose expiry <= now_sec.
    void prune_replay_locked(uint64_t now_sec);

    mutable std::mutex mu_;
    std::map<int, TokenBucket> peer_buckets_;
    std::map<std::array<uint8_t, 20>, uint64_t> mik_last_accept_;
    std::map<std::pair<std::array<uint8_t, 20>, int>, uint64_t> mik_peer_last_accept_;
    uint64_t last_prune_sec_ = 0;

    // Replay cache: FIFO deque of (expiry_sec, key) + set for O(log n) lookup.
    std::deque<std::pair<uint64_t, std::array<uint8_t, 32>>> replay_fifo_;
    std::set<std::array<uint8_t, 32>> replay_set_;
};

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_SAMPLE_RATE_LIMITER_H
