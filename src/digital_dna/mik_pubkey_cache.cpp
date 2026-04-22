// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <digital_dna/mik_pubkey_cache.h>

#include <dfmp/dfmp.h>          // Identity
#include <dfmp/identity_db.h>   // CIdentityDB
#include <dfmp/mik.h>           // MIK_PUBKEY_SIZE

#include <algorithm>

namespace digital_dna {

namespace {
inline bool IsZeroMIK(const std::array<uint8_t, 20>& mik) {
    for (auto b : mik) if (b != 0) return false;
    return true;
}
} // namespace

MikPubkeyCache::MikPubkeyCache(const DFMP::CIdentityDB* identity_db)
    : identity_db_(identity_db) {}

void MikPubkeyCache::Insert(const std::array<uint8_t, 20>& mik,
                            const std::vector<uint8_t>& pubkey) {
    if (IsZeroMIK(mik)) return;
    if (pubkey.size() != DFMP::MIK_PUBKEY_SIZE) return;

    std::lock_guard<std::mutex> lk(mu_);

    auto it = index_.find(mik);
    if (it != index_.end()) {
        // Already cached (pubkeys are immutable per MIK). Just refresh LRU.
        TouchLocked(it->second);
        return;
    }

    lru_.push_front(Entry{mik, pubkey});
    index_[mik] = lru_.begin();
    TrimLocked();
}

bool MikPubkeyCache::Lookup(const std::array<uint8_t, 20>& mik,
                            std::vector<uint8_t>& pubkey_out) {
    if (IsZeroMIK(mik)) return false;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = index_.find(mik);
        if (it != index_.end()) {
            pubkey_out = it->second->pubkey;
            TouchLocked(it->second);
            return true;
        }
    }

    // Cache miss — read through to LevelDB if available.
    if (!identity_db_) return false;

    DFMP::Identity id(mik.data());
    std::vector<uint8_t> db_pubkey;
    if (!identity_db_->GetMIKPubKey(id, db_pubkey)) {
        return false;
    }
    if (db_pubkey.size() != DFMP::MIK_PUBKEY_SIZE) {
        return false;  // Defensive; DB should never store wrong-size pubkey.
    }

    pubkey_out = db_pubkey;

    // Cache for next lookup. Insert() handles duplicates if another thread
    // raced us here.
    std::lock_guard<std::mutex> lk(mu_);
    auto it = index_.find(mik);
    if (it != index_.end()) {
        TouchLocked(it->second);
    } else {
        lru_.push_front(Entry{mik, std::move(db_pubkey)});
        index_[mik] = lru_.begin();
        TrimLocked();
    }
    return true;
}

void MikPubkeyCache::Evict(const std::array<uint8_t, 20>& mik) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = index_.find(mik);
    if (it == index_.end()) return;
    lru_.erase(it->second);
    index_.erase(it);
}

void MikPubkeyCache::Clear() {
    std::lock_guard<std::mutex> lk(mu_);
    lru_.clear();
    index_.clear();
}

bool MikPubkeyCache::DbStillHasMIK(const std::array<uint8_t, 20>& mik) const {
    if (!identity_db_) return true;  // Cache-only mode: defer to cache state.
    DFMP::Identity id(mik.data());
    return identity_db_->HasMIKPubKey(id);
}

size_t MikPubkeyCache::Size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return index_.size();
}

void MikPubkeyCache::SetCapacityForTests(size_t new_max) {
    std::lock_guard<std::mutex> lk(mu_);
    max_entries_ = std::max<size_t>(new_max, 1);
    TrimLocked();
}

void MikPubkeyCache::TouchLocked(ListIt it) {
    // Move `it` to the front of `lru_`.
    if (it == lru_.begin()) return;
    lru_.splice(lru_.begin(), lru_, it);
}

void MikPubkeyCache::TrimLocked() {
    while (lru_.size() > max_entries_) {
        auto& back = lru_.back();
        index_.erase(back.mik);
        lru_.pop_back();
    }
}

} // namespace digital_dna
