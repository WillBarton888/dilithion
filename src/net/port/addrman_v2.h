// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 1 starting point — port of Bitcoin Core's AddrMan (v28.0).
// This is a SKELETON. Declarations only. Implementation lands in Phase 1
// when it begins. Code compiles when included alongside addrman_v2.cpp
// (also a Phase-1 deliverable).
//
// Bitcoin Core source for this port:
//   https://github.com/bitcoin/bitcoin/blob/v28.0/src/addrman.h
//   https://github.com/bitcoin/bitcoin/blob/v28.0/src/addrman.cpp
//   https://github.com/bitcoin/bitcoin/blob/v28.0/src/addrman_impl.h
//
// Architecture: implements net/iaddress_manager.h.
// MIT-licensed source per Bitcoin Core; this port preserves attribution.

#ifndef DILITHION_NET_PORT_ADDRMAN_V2_H
#define DILITHION_NET_PORT_ADDRMAN_V2_H

#include <net/iaddress_manager.h>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace dilithion::net::port {

// ============================================================================
// Configuration constants — from Bitcoin Core's addrman_impl.h
// ============================================================================

// Total number of buckets in the "new" (untried) table.
constexpr int ADDRMAN_NEW_BUCKET_COUNT = 1024;

// Total number of buckets in the "tried" (verified-reachable) table.
constexpr int ADDRMAN_TRIED_BUCKET_COUNT = 256;

// Buckets to look in to determine if an address is in "new".
constexpr int ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64;

// Buckets a particular address can land in, in the "new" table.
constexpr int ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8;

// In each bucket: addresses go into one of N positions, deterministically
// chosen by hash so the same address always lands in the same slot.
constexpr int ADDRMAN_BUCKET_SIZE = 64;

// Number of buckets a tried-table entry can land in.
constexpr int ADDRMAN_TRIED_BUCKETS_PER_ADDRESS = 8;

// Min number of failed connection attempts in a row before considered
// "terrible" and eligible for eviction.
constexpr int ADDRMAN_RETRIES = 3;

// How many recently-failed attempts make an address "terrible".
constexpr int ADDRMAN_MAX_FAILURES = 10;

// Minimum quality (success rate) required to remain in tried table.
constexpr double ADDRMAN_MIN_QUALITY = 0.05;

// Selection bias towards tried table, expressed as percentage.
// Higher = more bias towards proven-good peers.
constexpr int ADDRMAN_SELECT_TRIED_PCT_DEFAULT = 50;

// ============================================================================
// AddrInfo — a single tracked address with its quality state.
// ============================================================================
//
// Mirrors bitcoin/src/addrman_impl.h::AddrInfo. Adds a Dilithion-specific
// optional MIK identity hint (advisory; not consensus).

struct AddrInfo {
    NetProtocol::CAddress addr;        // The actual address+port
    NetProtocol::CAddress source;      // Address we learned this peer from
    int64_t last_try_secs = 0;         // Last connection attempt (epoch secs)
    int64_t last_success_secs = 0;     // Last successful connection
    int64_t last_count_attempt_secs = 0;  // Last attempt counted in n_attempts
    int n_attempts = 0;                // Recent failed attempts in a row
    bool in_tried = false;             // Currently in tried table
    int random_pos = -1;               // Index in vRandom

    // Dilithion extension — advisory MIK hint, see iaddress_manager.h.
    std::vector<uint8_t> mik_identity;

    // Returns true if this peer should be evicted (too many recent failures
    // or never-successful + old enough).
    bool IsTerrible(int64_t now_secs) const;

    // Quality score for tie-breaking selection — Bitcoin uses exponential
    // backoff over recent success rate.
    double GetChance(int64_t now_secs) const;
};

// ============================================================================
// CAddrMan_v2 — concrete implementation of IAddressManager.
// ============================================================================
//
// Phase 1 deliverable. Replaces src/net/addrman.{h,cpp} once Phase 1 lands.
// The "_v2" suffix is the cutover marker; rename to CAddrMan in Phase 7.

class CAddrMan_v2 final : public IAddressManager {
public:
    CAddrMan_v2();
    ~CAddrMan_v2() override;

    // ---- IAddressManager interface ----
    bool Add(const NetProtocol::CAddress& addr,
             const NetProtocol::CAddress& source) override;

    void RecordAttempt(const NetProtocol::CAddress& addr,
                       ConnectionOutcome outcome) override;

    std::optional<NetProtocol::CAddress> Select(OutboundClass cls) override;

    std::vector<NetProtocol::CAddress> GetAddresses(
        size_t max_count,
        size_t max_pct,
        std::optional<int> network_filter) override;

    bool Save() override;
    bool Load() override;
    size_t Size() const override;

    void SetPeerMIKHint(const NetProtocol::CAddress& addr,
                        const std::vector<uint8_t>& mik_identity) override;

    // Set persistence path (called at construction by node startup).
    // Default is "<datadir>/peers.dat".
    void SetDataPath(const std::string& path);

    // For tests: deterministic key for bucket selection. In production this
    // is randomized at first run and persisted in peers.dat.
    void SetBucketSecret(const uint256& key);

private:
    // Mutex protects all member state below.
    mutable std::mutex m_mutex;

    // Path to peers.dat for persistence.
    std::string m_data_path;

    // Per-instance secret for bucket selection (anti-eclipse — different
    // nodes bucket addresses differently).
    uint256 m_bucket_secret;

    // Address → AddrInfo (the source of truth).
    std::map<int, AddrInfo> m_addr_info;
    int m_next_id = 1;

    // Address-string → id map for quick lookup.
    std::map<std::string, int> m_id_by_addr;

    // The "new" table — N buckets, each with M slots.
    std::vector<std::vector<int>> m_new_buckets;

    // The "tried" table — proven-good peers.
    std::vector<std::vector<int>> m_tried_buckets;

    // For random selection — shuffle this and pop.
    std::vector<int> m_random;

    // ---- Internal helpers (Bitcoin Core: AddrManImpl::*) ----

    // Hash an address into one of the N "new" buckets.
    int GetNewBucket(const NetProtocol::CAddress& addr,
                     const NetProtocol::CAddress& source) const;

    // Hash an address into one of the N "tried" buckets.
    int GetTriedBucket(const NetProtocol::CAddress& addr) const;

    // Within a bucket, hash to a slot.
    int GetBucketPosition(int bucket, bool tried,
                          const NetProtocol::CAddress& addr) const;

    // Promote an address from "new" to "tried" after successful connection.
    void MakeTried(int id);

    // Evict a terrible address from a bucket.
    void EvictFromBucket(int bucket, int slot, bool tried);

    // Pick a candidate from the tried table (biased random).
    std::optional<int> SelectFromTried() const;

    // Pick a candidate from the new table.
    std::optional<int> SelectFromNew() const;
};

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_ADDRMAN_V2_H
