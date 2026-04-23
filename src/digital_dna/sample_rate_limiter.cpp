// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include "sample_rate_limiter.h"

#include <crypto/sha3.h>

#include <algorithm>

namespace digital_dna {

void DNASampleRateLimiter::refill(TokenBucket& b, uint64_t now_sec) {
    if (now_sec <= b.last_refill_sec) return;
    uint64_t elapsed = now_sec - b.last_refill_sec;
    double added = static_cast<double>(elapsed) / PEER_BUCKET_REFILL_SEC;
    b.tokens = std::min(PEER_BUCKET_BURST, b.tokens + added);
    b.last_refill_sec = now_sec;
}

DNASampleRateLimiter::TokenBucket&
DNASampleRateLimiter::get_bucket_locked(int peer_id, uint64_t now_sec) {
    auto& bucket = peer_buckets_[peer_id];
    if (bucket.last_refill_sec == 0) {
        // First observation of this peer: start at full burst.
        bucket.tokens = PEER_BUCKET_BURST;
        bucket.last_refill_sec = now_sec;
    } else {
        refill(bucket, now_sec);
    }
    return bucket;
}

bool DNASampleRateLimiter::check_mik_locked(
    int peer_id,
    const std::array<uint8_t, 20>& mik,
    uint64_t now_sec) const
{
    auto mik_it = mik_last_accept_.find(mik);
    if (mik_it != mik_last_accept_.end() &&
        now_sec < mik_it->second + MIK_GLOBAL_MIN_SEC) {
        return false;
    }
    auto pair_key = std::make_pair(mik, peer_id);
    auto mp_it = mik_peer_last_accept_.find(pair_key);
    if (mp_it != mik_peer_last_accept_.end() &&
        now_sec < mp_it->second + MIK_PEER_MIN_SEC) {
        return false;
    }
    return true;
}

void DNASampleRateLimiter::commit_mik_locked(
    int peer_id,
    const std::array<uint8_t, 20>& mik,
    uint64_t now_sec)
{
    mik_last_accept_[mik] = now_sec;
    mik_peer_last_accept_[std::make_pair(mik, peer_id)] = now_sec;
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

void DNASampleRateLimiter::prune_replay_locked(uint64_t now_sec) {
    while (!replay_fifo_.empty() && replay_fifo_.front().first <= now_sec) {
        replay_set_.erase(replay_fifo_.front().second);
        replay_fifo_.pop_front();
    }
}

std::array<uint8_t, 32> DNASampleRateLimiter::replay_key(
    const std::array<uint8_t, 20>& mik,
    uint64_t ts,
    uint64_t nonce)
{
    uint8_t buf[20 + 8 + 8];
    std::copy(mik.begin(), mik.end(), buf);
    for (int i = 0; i < 8; ++i) buf[20 + i] = static_cast<uint8_t>((ts >> (8 * i)) & 0xFFu);
    for (int i = 0; i < 8; ++i) buf[28 + i] = static_cast<uint8_t>((nonce >> (8 * i)) & 0xFFu);
    std::array<uint8_t, 32> out;
    SHA3_256(buf, sizeof(buf), out.data());
    return out;
}

DNASampleRateLimiter::Reject DNASampleRateLimiter::allow_detail(
    int peer_id,
    const std::array<uint8_t, 20>& mik,
    uint64_t now_sec)
{
    std::lock_guard<std::mutex> lock(mu_);
    prune_locked(now_sec);

    auto& bucket = get_bucket_locked(peer_id, now_sec);
    if (bucket.tokens < 1.0) {
        return Reject::PEER_BUCKET;
    }

    auto mik_it = mik_last_accept_.find(mik);
    if (mik_it != mik_last_accept_.end() &&
        now_sec < mik_it->second + MIK_GLOBAL_MIN_SEC) {
        return Reject::MIK_GLOBAL;
    }

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

// ---- Staged (Phase 1.5) ---------------------------------------------------

bool DNASampleRateLimiter::consume_peer_bucket(int peer_id, uint64_t now_sec) {
    std::lock_guard<std::mutex> lock(mu_);
    prune_locked(now_sec);
    auto& bucket = get_bucket_locked(peer_id, now_sec);
    if (bucket.tokens < 1.0) return false;
    bucket.tokens -= 1.0;
    return true;
}

bool DNASampleRateLimiter::check_mik_limits(
    int peer_id,
    const std::array<uint8_t, 20>& mik,
    uint64_t now_sec)
{
    std::lock_guard<std::mutex> lock(mu_);
    return check_mik_locked(peer_id, mik, now_sec);
}

void DNASampleRateLimiter::commit_mik_limits(
    int peer_id,
    const std::array<uint8_t, 20>& mik,
    uint64_t now_sec)
{
    std::lock_guard<std::mutex> lock(mu_);
    commit_mik_locked(peer_id, mik, now_sec);
}

bool DNASampleRateLimiter::replay_seen(
    const std::array<uint8_t, 20>& mik,
    uint64_t ts,
    uint64_t nonce)
{
    auto key = replay_key(mik, ts, nonce);
    std::lock_guard<std::mutex> lock(mu_);
    // Don't prune here — we want lookup to be idempotent. Staleness only
    // matters at record time, where we prune before inserting.
    return replay_set_.find(key) != replay_set_.end();
}

void DNASampleRateLimiter::replay_record(
    const std::array<uint8_t, 20>& mik,
    uint64_t ts,
    uint64_t nonce,
    uint64_t now_sec)
{
    auto key = replay_key(mik, ts, nonce);
    std::lock_guard<std::mutex> lock(mu_);
    prune_replay_locked(now_sec);
    if (replay_set_.insert(key).second) {
        replay_fifo_.emplace_back(now_sec + REPLAY_TTL_SEC, key);
    }
}

// ---- Test helpers ---------------------------------------------------------

void DNASampleRateLimiter::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    peer_buckets_.clear();
    mik_last_accept_.clear();
    mik_peer_last_accept_.clear();
    replay_fifo_.clear();
    replay_set_.clear();
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

size_t DNASampleRateLimiter::replay_cache_size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return replay_set_.size();
}

} // namespace digital_dna
