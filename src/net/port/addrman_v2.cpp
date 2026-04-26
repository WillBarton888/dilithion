// Copyright (c) 2026 The Dilithion Core developers
// Copyright (c) 2012 Pieter Wuille (algorithm)
// Copyright (c) 2012-2024 The Bitcoin Core developers (algorithm)
// Distributed under the MIT software license
//
// AddrMan v2 — implementation of IAddressManager.
//
// Algorithm faithful to bitcoin/src/addrman.cpp v28.0:
//   * Tried (256 buckets x 64 slots) and new (1024 x 64) tables.
//   * Per-instance secret nKey randomizes bucket selection (anti-Sybil).
//   * Test-before-evict for tried-table collisions.
//   * Stochastic-multiplicity placement in new table.
//
// C++ idiom Dilithion-native:
//   * std::mutex (no upstream EXCLUSIVE_LOCKS_REQUIRED annotations).
//   * std::map indexed by CService (no unordered_map+CServiceHash).
//   * std::mt19937_64 seeded from std::random_device.
//   * SHA-3-256-keyed bucket hash (replaces upstream's HashWriter+SHA-256).
//   * int64_t Unix seconds (no NodeSeconds chrono wrapper).
//   * Manual std::ostream/std::istream serialization.
//
// Phase 1 Day 1 PM scope (this commit):
//   * Constructor / destructor
//   * Find / Create / Delete / SwapRandom
//   * IsTerrible / GetChance (AddrInfo helpers)
//   * GetTriedBucket / GetNewBucket / GetBucketPosition (free-fn bucket math)
//   * AddInternal / Add (entry point)
//   * MakeTried / ClearNew (bucket transitions)
//   * Stubs for: RecordAttempt, Select, GetAddresses, Save, Load,
//     ResolveTriedCollisions, AttemptInternal, GoodInternal,
//     ConnectedInternal, SelectInternal — Day 2 work.

#include <net/port/addrman_v2.h>
#include <net/port/addrman_hash.h>
#include <net/netaddress_dilithion.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

namespace dilithion::net::port {

// ============================================================================
// Local helpers (anonymous namespace — no external linkage)
// ============================================================================
namespace {

// ----------------------------------------------------------------------------
// Time
// ----------------------------------------------------------------------------
// Single canonical time source for AddrMan internal bookkeeping.
// Returns Unix seconds. Tests can shadow this if determinism is needed (Day 3).
int64_t NowSecs()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ----------------------------------------------------------------------------
// Address-key bytes
// ----------------------------------------------------------------------------
// Returns the 18-byte (16 IPv6 + 2 port) canonical key for a CService.
// Equivalent to upstream's CAddress::GetKey() — ip+port form unique-by-address.
std::vector<uint8_t> ServiceKeyBytes(const CService& addr)
{
    std::vector<uint8_t> out;
    out.reserve(18);
    const uint8_t* ip = addr.GetAddrBytes();
    out.insert(out.end(), ip, ip + 16);
    uint16_t port = addr.GetPort();
    out.push_back(static_cast<uint8_t>(port & 0xff));
    out.push_back(static_cast<uint8_t>((port >> 8) & 0xff));
    return out;
}

// ----------------------------------------------------------------------------
// Bucket math — SHA-3 substitution for upstream's HashWriter+SHA-256.
// ----------------------------------------------------------------------------
//
// Layout matches bitcoin/src/addrman.cpp v28.0 lines 48-67 byte-for-byte except
// for the hash function: same input order, same modular arithmetic, same return
// type. Reviewer can diff the args list against upstream.

// In which "tried" bucket does this address belong?
//   hash1 = SHA3_64(nKey || addr_key)
//   hash2 = SHA3_64(nKey || group(addr) || (hash1 % BUCKETS_PER_GROUP))
//   bucket = hash2 % TRIED_BUCKET_COUNT
int GetTriedBucket(const uint256& nKey, const CService& addr)
{
    std::vector<uint8_t> addr_key = ServiceKeyBytes(addr);
    std::vector<uint8_t> group = static_cast<const CNetAddr&>(addr).GetGroup();

    uint64_t hash1 = BucketHash64({AsBytes(nKey), addr_key});
    uint64_t hash2 = BucketHash64({
        AsBytes(nKey),
        group,
        AsBytes(static_cast<uint64_t>(hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP)),
    });
    return static_cast<int>(hash2 % ADDRMAN_TRIED_BUCKET_COUNT);
}

// In which "new" bucket does this address+source pair belong?
//   hash1 = SHA3_64(nKey || group(addr) || group(source))
//   hash2 = SHA3_64(nKey || group(source) || (hash1 % NEW_BUCKETS_PER_SOURCE_GROUP))
//   bucket = hash2 % NEW_BUCKET_COUNT
int GetNewBucket(const uint256& nKey, const CService& addr, const CNetAddr& source)
{
    std::vector<uint8_t> addr_group = static_cast<const CNetAddr&>(addr).GetGroup();
    std::vector<uint8_t> src_group = source.GetGroup();

    uint64_t hash1 = BucketHash64({AsBytes(nKey), addr_group, src_group});
    uint64_t hash2 = BucketHash64({
        AsBytes(nKey),
        src_group,
        AsBytes(static_cast<uint64_t>(hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)),
    });
    return static_cast<int>(hash2 % ADDRMAN_NEW_BUCKET_COUNT);
}

// In which slot of the chosen bucket should this address sit?
//   hash1 = SHA3_64(nKey || ('N' or 'K') || bucket || addr_key)
//   slot = hash1 % BUCKET_SIZE
int GetBucketPosition(const uint256& nKey, bool fNew, int bucket, const CService& addr)
{
    std::vector<uint8_t> addr_key = ServiceKeyBytes(addr);
    uint8_t tag = fNew ? uint8_t{'N'} : uint8_t{'K'};
    uint64_t hash1 = BucketHash64({
        AsBytes(nKey),
        AsBytes(tag),
        AsBytes(static_cast<uint64_t>(bucket)),
        addr_key,
    });
    return static_cast<int>(hash1 % ADDRMAN_BUCKET_SIZE);
}

}  // anonymous namespace

// ============================================================================
// AddrInfo
// ============================================================================

// Mirrors bitcoin/src/addrman.cpp::AddrInfo::IsTerrible (v28.0 lines 69-92).
// All durations expressed in Unix seconds (Dilithion idiom).
bool AddrInfo::IsTerrible(int64_t now_secs) const
{
    // Never remove an entry tried in the last minute — too eager to evict
    // would lose addrs we just got an inflight attempt to.
    if (now_secs - last_try_secs <= 60 && now_secs >= last_try_secs) {
        return false;
    }

    // "Came in a flying DeLorean." Wire-time more than 10 minutes in the
    // future means the source clock is wrong or the address is forged.
    // addr.time is uint32 Unix seconds (32-bit roll-over in 2106 — fine).
    int64_t addr_time = static_cast<int64_t>(addr.time);
    if (addr_time > now_secs + 10 * 60) {
        return true;
    }

    // Not seen in 30 days — cold address.
    if (now_secs - addr_time > ADDRMAN_HORIZON_SECS) {
        return true;
    }

    // Tried N times and never a single success.
    if (last_success_secs == 0 && n_attempts >= ADDRMAN_RETRIES) {
        return true;
    }

    // Recent string of failures with no recent success.
    if (now_secs - last_success_secs > ADDRMAN_MIN_FAIL_SECS &&
        n_attempts >= ADDRMAN_MAX_FAILURES) {
        return true;
    }

    return false;
}

// Mirrors bitcoin/src/addrman.cpp::AddrInfo::GetChance (v28.0 lines 94-107).
double AddrInfo::GetChance(int64_t now_secs) const
{
    double chance = 1.0;

    // Deprioritize attempts in the last 10 minutes (give them time to resolve).
    if (now_secs - last_try_secs < 10 * 60) {
        chance *= 0.01;
    }

    // 66% penalty per failed attempt, capped at 8 to avoid pow(0.66,N)
    // becoming negligible (~0.036) and starving large-failure-count entries.
    int n = std::min(n_attempts, 8);
    chance *= std::pow(0.66, n);

    return chance;
}

void AddrInfo::SerializeTo(std::ostream& /*os*/) const
{
    // TODO Day 2 PM: write [time, services, ip, port, source, last_success_secs,
    // n_attempts, in_tried_flag] in well-defined byte order. Format spec lives
    // alongside CAddrMan_v2::Save() so they evolve together.
}

void AddrInfo::DeserializeFrom(std::istream& /*is*/)
{
    // TODO Day 2 PM: counterpart of SerializeTo.
}

// ============================================================================
// CAddrMan_v2 — construction
// ============================================================================

CAddrMan_v2::CAddrMan_v2()
{
    // Initialize bucket grids to 0 (no entry — id 0 is reserved as sentinel).
    // The header default-initializes to {} which gives 0; redundant assignment
    // here costs nothing and makes intent explicit.
    for (int b = 0; b < ADDRMAN_TRIED_BUCKET_COUNT; ++b) {
        for (int s = 0; s < ADDRMAN_BUCKET_SIZE; ++s) {
            m_tried_buckets[b][s] = 0;
        }
    }
    for (int b = 0; b < ADDRMAN_NEW_BUCKET_COUNT; ++b) {
        for (int s = 0; s < ADDRMAN_BUCKET_SIZE; ++s) {
            m_new_buckets[b][s] = 0;
        }
    }

    // Seed the bucket secret from std::random_device. Replaced when Load()
    // reads a persisted key, or when SetBucketSecret() is called by tests.
    std::random_device rd;
    m_rng.seed(static_cast<uint64_t>(rd()) ^
               (static_cast<uint64_t>(rd()) << 32));
    for (int i = 0; i < 4; ++i) {
        uint64_t r = m_rng();
        std::memcpy(m_bucket_secret.data + i * 8, &r, 8);
    }
}

CAddrMan_v2::~CAddrMan_v2() = default;

// ============================================================================
// Configuration
// ============================================================================

void CAddrMan_v2::SetDataPath(const std::string& path)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_data_path = path;
}

void CAddrMan_v2::SetBucketSecret(const uint256& key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_bucket_secret = key;
    // Re-seed RNG deterministically from the key so tests get reproducible
    // selection ordering. First 8 bytes interpreted as little-endian uint64.
    uint64_t seed = 0;
    for (int i = 0; i < 8; ++i) {
        seed |= static_cast<uint64_t>(key.data[i]) << (i * 8);
    }
    m_rng.seed(seed);
}

// ============================================================================
// Internal table operations — caller holds m_mutex.
// ============================================================================

// Find an entry by its CService key. Returns nullptr if not present.
AddrInfo* CAddrMan_v2::Find(const CService& addr, int* out_id)
{
    auto it = m_id_by_addr.find(addr);
    if (it == m_id_by_addr.end()) {
        return nullptr;
    }
    if (out_id) {
        *out_id = it->second;
    }
    auto info_it = m_info.find(it->second);
    if (info_it == m_info.end()) {
        // Inconsistent state — m_id_by_addr and m_info disagree. This would
        // indicate a Delete() bug; assert in debug, return nullptr in release.
        assert(false && "m_id_by_addr and m_info inconsistent");
        return nullptr;
    }
    return &info_it->second;
}

// Create a fresh entry. Caller is responsible for any subsequent bucket
// placement (AddInternal does it; Load() does it directly).
//
// Mirrors upstream's `Create` (addrman.cpp:416-430).
AddrInfo* CAddrMan_v2::Create(const NetProtocol::CAddress& addr,
                              const CNetAddr& src,
                              int* out_id)
{
    int id = m_next_id++;

    AddrInfo info(addr, src);
    info.random_pos = static_cast<int>(m_random.size());

    m_info[id] = info;
    m_id_by_addr[ToService(addr)] = id;
    m_random.push_back(id);
    ++m_new_count;

    // Per-network counter — uses the network-of-the-address (CNetAddr::GetNetwork()).
    int net = static_cast<int>(ToNetAddr(addr).GetNetwork());
    ++m_network_counts[net].n_new;

    if (out_id) {
        *out_id = id;
    }
    return &m_info[id];
}

// Delete an entry. Caller MUST verify it's not in tried and has 0 ref-count.
//
// Mirrors upstream's `Delete` (addrman.cpp:456-471).
void CAddrMan_v2::Delete(int id)
{
    auto info_it = m_info.find(id);
    assert(info_it != m_info.end() && "Delete called on unknown id");
    AddrInfo& info = info_it->second;
    assert(!info.in_tried && "Delete called on tried entry");
    assert(info.n_ref_count == 0 && "Delete called on entry still in new buckets");

    // Move the to-be-deleted entry to the back of m_random, then pop.
    SwapRandom(static_cast<unsigned int>(info.random_pos),
               static_cast<unsigned int>(m_random.size() - 1));

    int net = static_cast<int>(ToNetAddr(info.addr).GetNetwork());
    auto net_it = m_network_counts.find(net);
    if (net_it != m_network_counts.end() && net_it->second.n_new > 0) {
        --net_it->second.n_new;
    }

    m_random.pop_back();
    m_id_by_addr.erase(ToService(info.addr));
    m_info.erase(info_it);
    --m_new_count;
}

// Swap two positions in m_random. Caller's burden to ensure both positions
// are in-range. Mirrors upstream's `SwapRandom` (addrman.cpp:432-454).
void CAddrMan_v2::SwapRandom(unsigned int pos_a, unsigned int pos_b) const
{
    if (pos_a == pos_b) return;

    assert(pos_a < m_random.size());
    assert(pos_b < m_random.size());

    int id_a = m_random[pos_a];
    int id_b = m_random[pos_b];

    auto it_a = m_info.find(id_a);
    auto it_b = m_info.find(id_b);
    assert(it_a != m_info.end());
    assert(it_b != m_info.end());

    it_a->second.random_pos = static_cast<int>(pos_b);
    it_b->second.random_pos = static_cast<int>(pos_a);

    m_random[pos_a] = id_b;
    m_random[pos_b] = id_a;
}

// ============================================================================
// Bucket transitions
// ============================================================================

// Free a slot in the new table. If the freed entry has no remaining refs
// after decrement, the entry itself is deleted from m_info.
//
// Mirrors upstream's `ClearNew` (addrman.cpp:473-489).
void CAddrMan_v2::ClearNew(int bucket, int slot)
{
    if (m_new_buckets[bucket][slot] == 0) return;

    int id = m_new_buckets[bucket][slot];
    auto it = m_info.find(id);
    assert(it != m_info.end());
    AddrInfo& info = it->second;
    assert(info.n_ref_count > 0);

    --info.n_ref_count;
    m_new_buckets[bucket][slot] = 0;

    if (info.n_ref_count == 0) {
        Delete(id);
    }
}

// Move an entry from the new table(s) into the tried table. Handles the
// eviction path (existing tried entry kicked back out into new) symmetrically.
//
// Mirrors upstream's `MakeTried` (addrman.cpp:491-548) byte-for-byte structure
// with sentinel adjusted from -1 to 0.
void CAddrMan_v2::MakeTried(int id)
{
    auto it = m_info.find(id);
    assert(it != m_info.end());
    AddrInfo& info = it->second;

    const CService addr_svc = ToService(info.addr);

    // Walk every new bucket starting from the canonical one for this addr/src
    // and clear ALL refs to this id. (One id can appear in up to 8 new
    // buckets — see ADDRMAN_NEW_BUCKETS_PER_ADDRESS.)
    const int start_bucket = GetNewBucket(m_bucket_secret, addr_svc, info.source);
    for (int n = 0; n < ADDRMAN_NEW_BUCKET_COUNT; ++n) {
        const int bucket = (start_bucket + n) % ADDRMAN_NEW_BUCKET_COUNT;
        const int pos = GetBucketPosition(m_bucket_secret, /*fNew=*/true, bucket, addr_svc);
        if (m_new_buckets[bucket][pos] == id) {
            m_new_buckets[bucket][pos] = 0;
            --info.n_ref_count;
            if (info.n_ref_count == 0) break;
        }
    }
    --m_new_count;
    int net = static_cast<int>(ToNetAddr(info.addr).GetNetwork());
    auto net_it = m_network_counts.find(net);
    if (net_it != m_network_counts.end() && net_it->second.n_new > 0) {
        --net_it->second.n_new;
    }

    assert(info.n_ref_count == 0);

    // Pick the destination tried bucket+slot.
    const int tried_bucket = GetTriedBucket(m_bucket_secret, addr_svc);
    const int tried_pos = GetBucketPosition(m_bucket_secret, /*fNew=*/false,
                                            tried_bucket, addr_svc);

    // If the slot is occupied, evict the existing entry into the new table.
    // The evicted entry doesn't get deleted unless it collides on placement
    // there too (handled by ClearNew below).
    if (m_tried_buckets[tried_bucket][tried_pos] != 0) {
        int id_evict = m_tried_buckets[tried_bucket][tried_pos];
        auto evict_it = m_info.find(id_evict);
        assert(evict_it != m_info.end());
        AddrInfo& info_evict = evict_it->second;

        info_evict.in_tried = false;
        m_tried_buckets[tried_bucket][tried_pos] = 0;
        int evict_net = static_cast<int>(ToNetAddr(info_evict.addr).GetNetwork());
        auto evict_net_it = m_network_counts.find(evict_net);
        if (evict_net_it != m_network_counts.end() && evict_net_it->second.n_tried > 0) {
            --evict_net_it->second.n_tried;
        }

        // Pick a destination bucket for the evictee in the new table.
        const CService evict_svc = ToService(info_evict.addr);
        const int new_bucket = GetNewBucket(m_bucket_secret, evict_svc, info_evict.source);
        const int new_pos = GetBucketPosition(m_bucket_secret, /*fNew=*/true,
                                              new_bucket, evict_svc);
        ClearNew(new_bucket, new_pos);
        assert(m_new_buckets[new_bucket][new_pos] == 0);

        info_evict.n_ref_count = 1;
        m_new_buckets[new_bucket][new_pos] = id_evict;
        ++m_new_count;
        ++m_network_counts[evict_net].n_new;
    }
    assert(m_tried_buckets[tried_bucket][tried_pos] == 0);

    m_tried_buckets[tried_bucket][tried_pos] = id;
    ++m_tried_count;
    info.in_tried = true;
    ++m_network_counts[net].n_tried;
}

// ============================================================================
// AddInternal — the only path by which a new address gets recorded.
// ============================================================================
//
// Mirrors upstream's `AddSingle` (addrman.cpp:550-624). Returns true iff a new
// entry was inserted into a new-table bucket.
bool CAddrMan_v2::AddInternal(const NetProtocol::CAddress& addr,
                              const CNetAddr& src,
                              int64_t time_penalty_secs)
{
    if (!ToService(addr).IsRoutable()) {
        return false;
    }

    int id = 0;
    AddrInfo* pinfo = Find(ToService(addr), &id);

    // No time-penalty for an address announcing itself.
    if (ToNetAddr(addr) == src) {
        time_penalty_secs = 0;
    }

    if (pinfo) {
        // Address already known — refresh its metadata if newer.
        const int64_t now = NowSecs();
        const bool currently_online = (now - static_cast<int64_t>(pinfo->addr.time)) < 24 * 3600;
        const int64_t update_interval = currently_online ? 3600 : 24 * 3600;

        if (static_cast<int64_t>(pinfo->addr.time) <
            static_cast<int64_t>(addr.time) - update_interval - time_penalty_secs) {
            int64_t new_time = std::max<int64_t>(0,
                static_cast<int64_t>(addr.time) - time_penalty_secs);
            pinfo->addr.time = static_cast<uint32_t>(new_time);
        }

        // Service flags accumulate.
        pinfo->addr.services |= addr.services;

        // No-op if incoming has nothing newer.
        if (addr.time <= pinfo->addr.time) {
            return false;
        }

        // Don't re-bucket entries already in tried.
        if (pinfo->in_tried) {
            return false;
        }

        // Already at max multiplicity — can't bump further.
        if (pinfo->n_ref_count == ADDRMAN_NEW_BUCKETS_PER_ADDRESS) {
            return false;
        }

        // Stochastic damping: each existing ref doubles the difficulty of
        // adding another. Bitcoin's anti-Sybil multiplicity throttle.
        if (pinfo->n_ref_count > 0) {
            const int factor = 1 << pinfo->n_ref_count;
            std::uniform_int_distribution<int> dist(0, factor - 1);
            if (dist(m_rng) != 0) {
                return false;
            }
        }
    } else {
        // Brand-new entry. Apply time-penalty before storing.
        pinfo = Create(addr, src, &id);
        int64_t adjusted_time = std::max<int64_t>(0,
            static_cast<int64_t>(pinfo->addr.time) - time_penalty_secs);
        pinfo->addr.time = static_cast<uint32_t>(adjusted_time);
    }

    // Place into a new-table bucket.
    const CService addr_svc = ToService(pinfo->addr);
    const int new_bucket = GetNewBucket(m_bucket_secret, addr_svc, src);
    const int new_pos = GetBucketPosition(m_bucket_secret, /*fNew=*/true,
                                          new_bucket, addr_svc);

    bool inserted = (m_new_buckets[new_bucket][new_pos] == 0);

    if (m_new_buckets[new_bucket][new_pos] != id) {
        if (!inserted) {
            // Collision — only overwrite if the existing entry is terrible
            // OR has more refs than this one (so we don't reduce diversity).
            AddrInfo& existing = m_info[m_new_buckets[new_bucket][new_pos]];
            if (existing.IsTerrible(NowSecs()) ||
                (existing.n_ref_count > 1 && pinfo->n_ref_count == 0)) {
                inserted = true;
            }
        }
        if (inserted) {
            ClearNew(new_bucket, new_pos);
            ++pinfo->n_ref_count;
            m_new_buckets[new_bucket][new_pos] = id;
        } else {
            // Couldn't place. If this was a fresh Create with no other refs,
            // it would orphan — Delete it.
            if (pinfo->n_ref_count == 0) {
                Delete(id);
            }
        }
    }
    return inserted;
}

// ============================================================================
// IAddressManager interface — public entry points (mutex taken at top).
// ============================================================================

bool CAddrMan_v2::Add(const NetProtocol::CAddress& addr,
                      const NetProtocol::CAddress& source)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // Single-address Add per IAddressManager contract. The Bitcoin Core batch
    // semantics live in upstream PeerManager; we expose a single-address API.
    // Source's CAddress is converted to CNetAddr (port irrelevant for source
    // grouping).
    return AddInternal(addr, ToNetAddr(source), /*time_penalty_secs=*/0);
}

void CAddrMan_v2::RecordAttempt(const NetProtocol::CAddress& addr,
                                ConnectionOutcome outcome)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    const CService svc = ToService(addr);
    const int64_t now = NowSecs();

    // Outcome → AddrMan-internal state updates. Mirrors the upstream split
    // between Connected_/Good_/Attempt_ at addrman.cpp:626-711, 868-885.
    switch (outcome) {
        case ConnectionOutcome::Success:
            // Successful peer-useful exchange — update wire-format time AND
            // promote into tried (with test-before-evict on collision).
            ConnectedInternal(svc, now);
            GoodInternal(svc, /*test_before_evict=*/true, now);
            break;

        case ConnectionOutcome::HandshakeFailed:
        case ConnectionOutcome::Timeout:
        case ConnectionOutcome::PeerMisbehaved:
            // The peer was unreachable or violated protocol — count this as
            // a real failure against its quality score.
            AttemptInternal(svc, /*count_failure=*/true, now);
            break;

        case ConnectionOutcome::LocalDisconnect:
            // We hung up first (eviction, shutdown). Don't penalize the peer.
            AttemptInternal(svc, /*count_failure=*/false, now);
            break;
    }
}

std::optional<NetProtocol::CAddress> CAddrMan_v2::Select(OutboundClass /*cls*/)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // TODO Day 2 PM: implement bucket-walk selection with chance_factor
    // ramp; honor OutboundClass (FullRelay / BlockRelay / Manual / Feeler).
    // Stubbed for Day 1 PM checkpoint compilation.
    return std::nullopt;
}

std::vector<NetProtocol::CAddress> CAddrMan_v2::GetAddresses(
    size_t /*max_count*/,
    size_t /*max_pct*/,
    std::optional<int> /*network_filter*/)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // TODO Day 2 PM: shuffle-pick a non-terrible random subset for ADDR
    // gossip. Stubbed for Day 1 PM checkpoint compilation.
    return {};
}

bool CAddrMan_v2::Save()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // TODO Day 2 PM: atomic tmp+rename write of peers.dat in the v2 format
    // (header byte, nKey, last_good_secs, entries with in_tried flag — buckets
    // rebuilt on Load from nKey). Returns true to satisfy the IAddressManager
    // contract until persistence lands; addresses live in memory only meanwhile.
    return true;
}

bool CAddrMan_v2::Load()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // TODO Day 2 PM: read peers.dat, rebuild m_info / m_id_by_addr / m_random
    // and re-run GetTriedBucket / GetNewBucket on every entry to populate the
    // bucket grids. Falls back to fresh-empty if file missing (per plan §2.1).
    // Returns true (= "no fatal error") for now so node startup proceeds.
    return true;
}

size_t CAddrMan_v2::Size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_random.size();
}

// ============================================================================
// Day-2 internal stubs (kept here to make the link-edit surface explicit).
// ============================================================================

// Mirrors upstream's Good_ (addrman.cpp:626-679). Promotes a known address
// from new to tried — with optional test-before-evict on collision.
//
// Returns true iff the address was moved into tried this call. False can mean
// "already in tried", "not found", "collision queued for resolution", or
// "test-before-evict skipped because slot was free". Callers don't currently
// distinguish — the IAddressManager contract only exposes RecordAttempt's
// void return.
bool CAddrMan_v2::GoodInternal(const CService& addr,
                               bool test_before_evict,
                               int64_t now_secs)
{
    int id = 0;
    m_last_good_secs = now_secs;

    AddrInfo* pinfo = Find(addr, &id);
    if (!pinfo) return false;
    AddrInfo& info = *pinfo;

    // Always update success/try metadata. nTime intentionally NOT touched
    // here — Bitcoin Core comment: "to avoid leaking information about
    // currently-connected peers" via ADDR gossip.
    info.last_success_secs = now_secs;
    info.last_try_secs = now_secs;
    info.n_attempts = 0;

    // Already tried? Nothing further to do.
    if (info.in_tried) return false;

    // Defensive: if the entry is in neither tried nor any new bucket, the
    // tables are inconsistent. Bail rather than corrupt further.
    if (info.n_ref_count == 0) return false;

    // Where would this addr land in tried?
    const int tried_bucket = GetTriedBucket(m_bucket_secret, addr);
    const int tried_pos = GetBucketPosition(m_bucket_secret, /*fNew=*/false,
                                            tried_bucket, addr);

    // If the slot is occupied AND caller asked for test-before-evict, queue
    // the candidate for ResolveTriedCollisions to settle later. Otherwise
    // proceed with eviction now.
    if (test_before_evict && m_tried_buckets[tried_bucket][tried_pos] != 0) {
        if (m_tried_collisions.size() < ADDRMAN_SET_TRIED_COLLISION_SIZE) {
            m_tried_collisions.insert(id);
        }
        return false;
    }

    MakeTried(id);
    return true;
}

// Mirrors upstream's Attempt_ (addrman.cpp:693-711). Records that we tried
// to connect; conditionally bumps the failure counter.
void CAddrMan_v2::AttemptInternal(const CService& addr,
                                  bool count_failure,
                                  int64_t now_secs)
{
    AddrInfo* pinfo = Find(addr);
    if (!pinfo) return;

    pinfo->last_try_secs = now_secs;

    // Debounce: only count this failure if the entry has been "good" since
    // its last counted attempt. Otherwise rapid-fire failures from a single
    // bad batch would inflate n_attempts unfairly.
    if (count_failure &&
        pinfo->last_count_attempt_secs < m_last_good_secs) {
        pinfo->last_count_attempt_secs = now_secs;
        ++pinfo->n_attempts;
    }
}

std::optional<std::pair<NetProtocol::CAddress, int64_t>>
CAddrMan_v2::SelectInternal(bool /*new_only*/)
{
    // TODO Day 2 PM
    return std::nullopt;
}

// Mirrors upstream's ResolveCollisions_ (addrman.cpp:903-963).
//
// For each address queued by GoodInternal as colliding with a tried slot:
//   * If the existing tried entry has succeeded recently → keep it, drop the
//     new one (it'll have to re-try later).
//   * If the existing tried entry has been unreachable in the test window →
//     evict it in favor of the new one.
//   * If neither is true and the test window has elapsed → force-evict.
//
// Caller need not hold m_mutex specially — this is private and called from
// public methods under their own lock. (Currently only RecordAttempt would
// invoke it, but the call site is added in Phase 4 / 6 PeerManager.)
void CAddrMan_v2::ResolveTriedCollisions()
{
    for (auto it = m_tried_collisions.begin(); it != m_tried_collisions.end();) {
        const int id_new = *it;
        bool erase_this = false;

        auto info_it = m_info.find(id_new);
        if (info_it == m_info.end()) {
            // Entry vanished (Delete called between queueing and resolution).
            erase_this = true;
        } else {
            AddrInfo& info_new = info_it->second;
            const CService addr_svc = ToService(info_new.addr);
            const int tried_bucket = GetTriedBucket(m_bucket_secret, addr_svc);
            const int tried_pos = GetBucketPosition(m_bucket_secret,
                                                    /*fNew=*/false,
                                                    tried_bucket, addr_svc);

            if (!addr_svc.IsRoutable()) {
                // Address became unroutable — drop quietly.
                erase_this = true;
            } else if (m_tried_buckets[tried_bucket][tried_pos] != 0) {
                const int id_old = m_tried_buckets[tried_bucket][tried_pos];
                AddrInfo& info_old = m_info[id_old];
                const int64_t now = NowSecs();

                if (now - info_old.last_success_secs < ADDRMAN_REPLACEMENT_SECS) {
                    // Old entry has connected successfully recently — keep it.
                    erase_this = true;
                } else if (now - info_old.last_try_secs < ADDRMAN_REPLACEMENT_SECS) {
                    // Old entry is being tested. Give it ≥60s to either
                    // succeed or fail clearly before we overrule.
                    if (now - info_old.last_try_secs > 60) {
                        GoodInternal(addr_svc, /*test_before_evict=*/false, now);
                        erase_this = true;
                    }
                } else if (now - info_new.last_success_secs > ADDRMAN_TEST_WINDOW_SECS) {
                    // Test window expired — force-evict to break the deadlock.
                    GoodInternal(addr_svc, /*test_before_evict=*/false, now);
                    erase_this = true;
                }
            } else {
                // Slot freed up since queueing — promote without contest.
                GoodInternal(addr_svc, /*test_before_evict=*/false, NowSecs());
                erase_this = true;
            }
        }

        if (erase_this) {
            it = m_tried_collisions.erase(it);
        } else {
            ++it;
        }
    }
}

// Mirrors upstream's Connected_ (addrman.cpp:868-885). Bumps the wire-format
// time on a known address — but only if it's stale by ≥20 minutes, to avoid
// generating ADDR-message churn from every successful tick.
void CAddrMan_v2::ConnectedInternal(const CService& addr, int64_t time_secs)
{
    AddrInfo* pinfo = Find(addr);
    if (!pinfo) return;

    constexpr int64_t kUpdateInterval = 20 * 60;  // 20 minutes
    if (time_secs - static_cast<int64_t>(pinfo->addr.time) > kUpdateInterval) {
        pinfo->addr.time = static_cast<uint32_t>(time_secs);
    }
}

// ============================================================================
// Test diagnostics
// ============================================================================

std::map<int, CAddrMan_v2::NetworkCounts> CAddrMan_v2::GetNetworkCountsForTest() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_network_counts;
}

}  // namespace dilithion::net::port
