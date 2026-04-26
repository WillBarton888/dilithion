// Copyright (c) 2026 The Dilithion Core developers
// Copyright (c) 2012 Pieter Wuille (algorithm)
// Copyright (c) 2012-2024 The Bitcoin Core developers (algorithm)
// Distributed under the MIT software license
//
// Phase 1 of the Bitcoin Core peer/IBD/chain-selection port.
// Algorithm faithful to Bitcoin Core v28.0 (src/addrman.{h,cpp,_impl.h}).
// C++ idiom Dilithion-native (std::mutex, std::map, std::mt19937_64, SHA-3,
// manual stream ops). Implements the FROZEN IAddressManager interface.
//
// Architecture document: .claude/contracts/bitcoin_core_port_architecture.md
// Phase 1 plan: .claude/contracts/port_phase_1_implementation_plan.md
//
// Design goals (from upstream):
//  * Keep address tables in-memory; asynchronously dump to peers.dat
//  * No (localized) attacker can fill the entire table with their nodes
//
// To that end:
//  * Addresses organized into buckets that store up to 64 entries each
//  * 1024 "new" buckets for unverified addresses (selected by source group)
//  * 256 "tried" buckets for verified-reachable addresses (selected by addr group)
//  * Per-bucket position chosen by full-address hash
//  * One address can occupy up to 8 different new buckets (multiplicity)
//  * Test-before-evict for tried-table collisions

#ifndef DILITHION_NET_PORT_ADDRMAN_V2_H
#define DILITHION_NET_PORT_ADDRMAN_V2_H

#include <net/iaddress_manager.h>
#include <net/netaddress.h>     // CNetAddr, CService, Network
#include <net/protocol.h>       // NetProtocol::CAddress (by-value member of AddrInfo)
#include <primitives/block.h>   // uint256

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace dilithion::net::port {

class NetGroupManager;  // forward decl from netgroup.h

// ============================================================================
// Constants — algorithm faithful to upstream bitcoin/src/addrman_impl.h v28.0
// ============================================================================

// Total number of buckets for tried addresses (1 << 8 = 256).
constexpr int32_t ADDRMAN_TRIED_BUCKET_COUNT_LOG2 = 8;
constexpr int ADDRMAN_TRIED_BUCKET_COUNT = 1 << ADDRMAN_TRIED_BUCKET_COUNT_LOG2;

// Total number of buckets for new addresses (1 << 10 = 1024).
constexpr int32_t ADDRMAN_NEW_BUCKET_COUNT_LOG2 = 10;
constexpr int ADDRMAN_NEW_BUCKET_COUNT = 1 << ADDRMAN_NEW_BUCKET_COUNT_LOG2;

// Maximum entries per bucket (1 << 6 = 64).
constexpr int32_t ADDRMAN_BUCKET_SIZE_LOG2 = 6;
constexpr int ADDRMAN_BUCKET_SIZE = 1 << ADDRMAN_BUCKET_SIZE_LOG2;

// Distinct tried-table buckets a single address group can occupy (anti-Sybil).
constexpr uint32_t ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8;

// Distinct new-table buckets a single source group can place addresses into.
constexpr uint32_t ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64;

// Maximum new-table multiplicity for one address (selection-chance booster).
constexpr int32_t ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8;

// Quality thresholds — Bitcoin Core uses chrono; we use seconds-since-epoch.
constexpr int64_t ADDRMAN_HORIZON_SECS = 30 * 24 * 3600;       // 30 days
constexpr int32_t ADDRMAN_RETRIES = 3;                          // Failed-attempt threshold for "terrible"
constexpr int32_t ADDRMAN_MAX_FAILURES = 10;                    // Successive-failure cap
constexpr int64_t ADDRMAN_MIN_FAIL_SECS = 7 * 24 * 3600;       // 7 days
constexpr int64_t ADDRMAN_REPLACEMENT_SECS = 4 * 3600;         // 4 hours
constexpr size_t ADDRMAN_SET_TRIED_COLLISION_SIZE = 10;         // Test-before-evict queue size
constexpr int64_t ADDRMAN_TEST_WINDOW_SECS = 40 * 60;          // Test-before-evict window

// File format version. Increment for any incompatible on-disk change.
// Current format: addresses + per-AddrInfo state, no MIK appendix (KISS).
constexpr uint8_t ADDRMAN_V2_FORMAT_VERSION = 1;

// ============================================================================
// AddrInfo — per-address tracked state
// ============================================================================
//
// Mirrors bitcoin/src/addrman_impl.h::AddrInfo. Held in m_info indexed by id.

struct AddrInfo {
    // Wire-format address state (services, time-last-seen, ip, port).
    NetProtocol::CAddress addr;

    // Network address of the peer that first told us about this address.
    // Used for source-group bucketing in the new table.
    CNetAddr source;

    // Last time we got a SUCCESSFUL connection to this peer (Unix seconds).
    // Default 0 = never connected successfully.
    int64_t last_success_secs = 0;

    // Last time we ATTEMPTED to connect (memory-only — not persisted).
    int64_t last_try_secs = 0;

    // Last time we counted an attempt against `n_attempts` (memory-only).
    // Bitcoin Core uses this to debounce rapid-fire failures from inflating
    // the counter unfairly.
    int64_t last_count_attempt_secs = 0;

    // Number of attempts since last_success. Drives "terrible" detection.
    int n_attempts = 0;

    // Reference count in new-table buckets (1..ADDRMAN_NEW_BUCKETS_PER_ADDRESS).
    int n_ref_count = 0;

    // True if this address is currently in the tried table.
    bool in_tried = false;

    // Position in vRandom shuffle (memory-only, mutable).
    mutable int random_pos = -1;

    AddrInfo() = default;
    AddrInfo(const NetProtocol::CAddress& a, const CNetAddr& src)
        : addr(a), source(src) {}

    // Determine whether the statistics about this entry are bad enough that
    // it can just be deleted. Mirrors upstream IsTerrible().
    bool IsTerrible(int64_t now_secs) const;

    // Relative chance this entry should be given when selecting nodes to
    // connect to. Mirrors upstream GetChance().
    double GetChance(int64_t now_secs) const;

    // Manual binary serialization (no SERIALIZE_METHODS macro — Dilithion idiom).
    void SerializeTo(std::ostream& os) const;
    void DeserializeFrom(std::istream& is);
};

// ============================================================================
// CAddrMan_v2 — implementation of IAddressManager
// ============================================================================
//
// Direct class (no PIMPL split) per Dilithion convention. All state private
// behind a single std::mutex. Public methods are thread-safe.

class CAddrMan_v2 final : public IAddressManager {
public:
    CAddrMan_v2();
    ~CAddrMan_v2() override;

    // Disable copy and move — single-instance per node.
    CAddrMan_v2(const CAddrMan_v2&) = delete;
    CAddrMan_v2& operator=(const CAddrMan_v2&) = delete;

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

    // ---- Configuration (called once at construction by node startup) ----

    // Path to peers.dat (default: empty, set by SetDataPath).
    void SetDataPath(const std::string& path);

    // Per-instance bucket-selection secret. In production, generated on first
    // run via std::random_device and persisted in peers.dat. Tests may inject
    // a deterministic key.
    void SetBucketSecret(const uint256& key);

    // ---- Test-only diagnostics ----

    // Snapshot of per-network counts. (Not in IAddressManager — used by tests.)
    struct NetworkCounts {
        size_t n_new = 0;
        size_t n_tried = 0;
    };
    std::map<int /*Network*/, NetworkCounts> GetNetworkCountsForTest() const;

private:
    // Mutex protects all member state. Public methods take this lock at entry.
    mutable std::mutex m_mutex;

    // Path to peers.dat for persistence.
    std::string m_data_path;

    // Per-instance secret used in all bucket-hash computations.
    uint256 m_bucket_secret;

    // Random source for selection bias. Seeded from std::random_device at
    // construction; tests can re-seed via SetBucketSecret (which doubles as
    // determinism control).
    mutable std::mt19937_64 m_rng;

    // Last-id counter — monotonic per-instance, reused only after Delete.
    int m_next_id = 1;

    // id  →  AddrInfo. Source of truth for address state.
    std::map<int, AddrInfo> m_info;

    // CService  →  id. Quick lookup by address.
    std::map<CService, int> m_id_by_addr;

    // Random-order id list. Shuffled in-place; used for GetAddresses output
    // and unbiased iteration. Mutable because shuffle is unobservable
    // outside the class.
    mutable std::vector<int> m_random;

    // Number of unique addresses currently in the tried table.
    int m_tried_count = 0;

    // Number of unique addresses currently in the new table (one entry per
    // unique address; multiplicity counted separately via n_ref_count).
    int m_new_count = 0;

    // Bucket grids: id at each [bucket][slot] position, or 0 if empty.
    int m_tried_buckets[ADDRMAN_TRIED_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE] = {};
    int m_new_buckets[ADDRMAN_NEW_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE] = {};

    // Last time Good() was successfully called. Initially 1 (== "never" as
    // the worst possible, but distinguishable from default-constructed 0
    // which we use as sentinel elsewhere).
    int64_t m_last_good_secs = 1;

    // Tried-table collisions awaiting test-before-evict resolution. Capped
    // at ADDRMAN_SET_TRIED_COLLISION_SIZE.
    std::set<int> m_tried_collisions;

    // Per-network counters (mainly for diagnostics / RPC).
    std::map<int /*Network as int*/, NetworkCounts> m_network_counts;

    // ---- Internal helpers (private; mutex held by caller) ----

    // Find an entry by service+port. Returns nullptr if not present.
    // Optionally returns the id via *out_id.
    AddrInfo* Find(const CService& addr, int* out_id = nullptr);

    // Create a new entry. Returns the entry pointer and (optionally) its id.
    // Caller is responsible for inserting into bucket grids.
    AddrInfo* Create(const NetProtocol::CAddress& addr,
                     const CNetAddr& src,
                     int* out_id = nullptr);

    // Delete an entry. Caller must ensure it's not in tried and has 0 refs.
    void Delete(int id);

    // Swap two positions in m_random.
    void SwapRandom(unsigned int pos_a, unsigned int pos_b) const;

    // Move an entry from new table to tried table.
    void MakeTried(int id);

    // Internal Add() — single address (Add() public is single-add only by
    // KISS / our IAddressManager interface, so no batch wrapper needed).
    bool AddInternal(const NetProtocol::CAddress& addr,
                     const CNetAddr& src,
                     int64_t time_penalty_secs);

    // Internal Good() — promote to tried; may trigger test-before-evict.
    bool GoodInternal(const CService& addr,
                      bool test_before_evict,
                      int64_t now_secs);

    // Internal Attempt() — record connection attempt.
    void AttemptInternal(const CService& addr,
                         bool count_failure,
                         int64_t now_secs);

    // Internal Select() — picks an address; respects new_only.
    std::optional<std::pair<NetProtocol::CAddress, int64_t>>
    SelectInternal(bool new_only);

    // Resolve any pending tried-table collisions (test-before-evict path).
    void ResolveTriedCollisions();

    // Connected — update last-success time. (Called from RecordAttempt(Success).)
    void ConnectedInternal(const CService& addr, int64_t time_secs);

    // Clear a position in the new table. The only place where new-bucket
    // entries are actually freed.
    void ClearNew(int bucket, int slot);
};

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_ADDRMAN_V2_H
