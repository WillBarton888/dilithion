// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include "sample_rate_limiter.h"

#include <algorithm>

namespace digital_dna {

void DNASampleRateLimiter::refill(TokenBucket& b, uint64_t now_sec) {
    if (now_sec <= b.last_refill_sec) return;
    uint64_t elapsed = now_sec - b.last_refill_sec;
    double added = static_cast<double>(elapsed) / PEER_BUCKET_REFILL_SEC;
    b.tokens = std::min(PEER_BUCKET_BURST, b.tokens + added);
    b.last_refill_sec = now_sec;
}

void DNASampleRateLimiter::prune_locked(uint64_t now_sec) {
    if (now_sec < last_prune_sec_ + PRUNE_IDLE_SEC) return;
    last_prune_sec_ = now_sec;

    for (auto it = peer_buckets_.begin(); it != peer_buckets_.end();) {
        if (now_sec > it->second.last_refill_sec &&
            now_sec - it->second.last_refill_sec > PRUNE_IDLE_SEC) {
            it = peer_buckets_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = mik_last_accept_.begin(); it != mik_last_accept_.end();) {
        if (now_sec > it->second && now_sec - it->second > PRUNE_IDLE_SEC) {
            it = mik_last_accept_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = mik_peer_last_accept_.begin(); it != mik_peer_last_accept_.end();) {
        if (now_sec > it->second && now_sec - it->second > PRUNE_IDLE_SEC) {
            it = mik_peer_last_accept_.erase(it);
        } else {
            ++it;
        }
    }
}

DNASampleRateLimiter::Reject DNASampleRateLimiter::allow_detail(
    int peer_id,
    const std::array<uint8_t, 20>& mik,
    uint64_t now_sec)
{
    std::lock_guard<std::mutex> lock(mu_);
    prune_locked(now_sec);

    // Layer 1: per-peer token bucket.
    auto& bucket = peer_buckets_[peer_id];
    if (bucket.last_refill_sec == 0) {
        // First observation of this peer: start at full burst.
        bucket.tokens = PEER_BUCKET_BURST;
        bucket.last_refill_sec = now_sec;
    } else {
        refill(bucket, now_sec);
    }
    if (bucket.tokens < 1.0) {
        return Reject::PEER_BUCKET;
    }

    // Layer 2: per-MIK global interval.
    auto mik_it = mik_last_accept_.find(mik);
    if (mik_it != mik_last_accept_.end() &&
        now_sec < mik_it->second + MIK_GLOBAL_MIN_SEC) {
        return Reject::MIK_GLOBAL;
    }

    // Layer 3: per-MIK-per-peer interval.
    auto pair_key = std::make_pair(mik, peer_id);
    auto mp_it = mik_peer_last_accept_.find(pair_key);
    if (mp_it != mik_peer_last_accept_.end() &&
        now_sec < mp_it->second + MIK_PEER_MIN_SEC) {
        return Reject::MIK_PEER;
    }

    // All checks passed — consume state.
    bucket.tokens -= 1.0;
    mik_last_accept_[mik] = now_sec;
    mik_peer_last_accept_[pair_key] = now_sec;
    return Reject::OK;
}

bool DNASampleRateLimiter::allow(int peer_id,
                                 const std::array<uint8_t, 20>& mik,
                                 uint64_t now_sec) {
    return allow_detail(peer_id, mik, now_sec) == Reject::OK;
}

void DNASampleRateLimiter::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    peer_buckets_.clear();
    mik_last_accept_.clear();
    mik_peer_last_accept_.clear();
    last_prune_sec_ = 0;
}

size_t DNASampleRateLimiter::peer_state_size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return peer_buckets_.size();
}

size_t DNASampleRateLimiter::mik_global_state_size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return mik_last_accept_.size();
}

size_t DNASampleRateLimiter::mik_peer_state_size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return mik_peer_last_accept_.size();
}

} // namespace digital_dna
