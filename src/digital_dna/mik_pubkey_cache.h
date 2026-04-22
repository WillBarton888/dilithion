// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DIGITAL_DNA_MIK_PUBKEY_CACHE_H
#define DILITHION_DIGITAL_DNA_MIK_PUBKEY_CACHE_H

/**
 * MIK → Dilithium3 pubkey cache (Phase 1.5 "Option D").
 *
 * Serves signature verification on the net thread without taking the
 * LevelDB path on every verify.
 *
 *   - Populated by block-connect callbacks: when a coinbase carries a
 *     registration-PoW MIK payload, the node inserts (mik, pubkey).
 *   - Read-through on miss: if we don't have the pubkey cached, we fall
 *     back to `CIdentityDB::GetMIKPubKey` and cache the result.
 *   - LRU-bounded at 10,000 entries (~120 active miners today, 100x
 *     headroom; 10k * ~2KB pubkey ≈ 20 MiB worst-case).
 *
 * Reorg handling: pubkeys are PoW-bound and usually immutable, but
 * `CIdentityDB::RemoveMIKPubKey` can drop a pubkey on chain disconnect
 * when `firstSeen == disconnect_height`. Rather than mirror every
 * disconnect event, the receiver calls `HasMIKPubKey` on the identity
 * database after a cache hit, before running Dilithium verify — if the
 * DB disagrees with the cache, the entry is evicted and the sample is
 * silently dropped. Cheap (microsecond-level DB existence check) and
 * strictly defensive: the DB is the source of truth.
 *
 * Thread model:
 *   - Writes from block-callback thread (Insert).
 *   - Reads from net thread (Lookup).
 *   - Evictions can come from either thread.
 *   - Single internal std::mutex; all operations O(log N) on the index.
 */

#include <array>
#include <cstdint>
#include <list>
#include <map>
#include <mutex>
#include <vector>

namespace DFMP { class CIdentityDB; }

namespace digital_dna {

class MikPubkeyCache {
public:
    /// Upper bound for LRU eviction. Tests may override via SetCapacityForTests.
    static constexpr size_t DEFAULT_MAX_ENTRIES = 10000;

    /// `identity_db` is the read-through source on cache miss. May be null
    /// (e.g. in unit tests that don't need fallback); a null source skips
    /// read-through and returns false on miss.
    explicit MikPubkeyCache(const DFMP::CIdentityDB* identity_db);

    /// Insert (mik, pubkey). If mik already present, this is a no-op and the
    /// LRU position is refreshed. Zero-MIK is rejected. Wrong-size pubkeys
    /// are rejected.
    void Insert(const std::array<uint8_t, 20>& mik,
                const std::vector<uint8_t>& pubkey);

    /// Lookup pubkey for MIK. On cache miss, falls back to the identity DB
    /// (if configured) and caches a hit. Returns true iff a pubkey was found.
    bool Lookup(const std::array<uint8_t, 20>& mik,
                std::vector<uint8_t>& pubkey_out);

    /// Remove an entry (called on reorg-driven disconnect or post-hit sanity
    /// check mismatch). Safe no-op if MIK not present.
    void Evict(const std::array<uint8_t, 20>& mik);

    /// Clear the cache. Mainly for tests.
    void Clear();

    /// Returns true if the identity DB still knows this MIK. Receiver calls
    /// this after a cache hit, before signature verification, to defend
    /// against stale cache entries after a reorg. Returns true if no DB is
    /// configured (cache-only mode, e.g. tests).
    bool DbStillHasMIK(const std::array<uint8_t, 20>& mik) const;

    /// Current number of cached entries. Mainly for tests and diagnostics.
    size_t Size() const;

    /// Test hook to lower the LRU cap for unit-testing eviction behaviour.
    /// Do not call outside tests.
    void SetCapacityForTests(size_t new_max);

private:
    struct Entry {
        std::array<uint8_t, 20> mik;
        std::vector<uint8_t> pubkey;
    };
    using ListIt = std::list<Entry>::iterator;

    // LRU bookkeeping (must be called under `mu_`). Moves `it` to the front.
    void TouchLocked(ListIt it);

    // Evict oldest entries until size <= max_entries_ (under `mu_`).
    void TrimLocked();

    const DFMP::CIdentityDB* identity_db_;
    mutable std::mutex mu_;
    std::list<Entry> lru_;  // front = most-recently-used
    std::map<std::array<uint8_t, 20>, ListIt> index_;
    size_t max_entries_ = DEFAULT_MAX_ENTRIES;
};

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_MIK_PUBKEY_CACHE_H
