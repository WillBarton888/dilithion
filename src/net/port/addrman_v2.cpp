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
// Implemented through Day 2 AM:
//   * Constructor / destructor
//   * Find / Create / Delete / SwapRandom (basic table ops)
//   * IsTerrible / GetChance (AddrInfo helpers)
//   * GetTriedBucket / GetNewBucket / GetBucketPosition (free-fn bucket math)
//   * AddInternal / Add (entry point with stochastic damping)
//   * MakeTried / ClearNew (bucket transitions)
//   * ConnectedInternal / AttemptInternal / GoodInternal (state updates)
//   * RecordAttempt (outcome dispatcher)
//   * ResolveTriedCollisions (test-before-evict resolver)
//   * SelectInternal / Select (bucket walk with chance_factor ramp)
//   * GetAddresses (random subset for ADDR gossip)
//   * AddrInfo::SerializeTo / DeserializeFrom (binary stream layout)
//   * Save / Load (atomic peers.dat persistence, tmp + rename pattern)
//
// Day 2 PM remaining: addrman_migrator (legacy peers.dat import) + initial
// addrman_tests.cpp port. Day 3: rest of tests + cutover.

#include <net/port/addrman_v2.h>
#include <net/port/addrman_hash.h>
#include <net/netaddress_dilithion.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#ifdef _WIN32
#include <windows.h>  // GetLastError, ERROR_FILE_NOT_FOUND
#endif

namespace dilithion::net::port {

// ============================================================================
// Local helpers (anonymous namespace — no external linkage)
// ============================================================================
namespace {

// ----------------------------------------------------------------------------
// Little-endian binary read/write helpers (for peers.dat persistence)
// ----------------------------------------------------------------------------

void WriteU8(std::ostream& os, uint8_t v)
{
    os.put(static_cast<char>(v));
}

void WriteU16(std::ostream& os, uint16_t v)
{
    char b[2] = {
        static_cast<char>(v & 0xff),
        static_cast<char>((v >> 8) & 0xff),
    };
    os.write(b, 2);
}

void WriteU32(std::ostream& os, uint32_t v)
{
    char b[4];
    for (int i = 0; i < 4; ++i) b[i] = static_cast<char>((v >> (i * 8)) & 0xff);
    os.write(b, 4);
}

void WriteU64(std::ostream& os, uint64_t v)
{
    char b[8];
    for (int i = 0; i < 8; ++i) b[i] = static_cast<char>((v >> (i * 8)) & 0xff);
    os.write(b, 8);
}

void WriteI64(std::ostream& os, int64_t v)
{
    WriteU64(os, static_cast<uint64_t>(v));
}

uint8_t ReadU8(std::istream& is)
{
    char b = 0;
    is.read(&b, 1);
    return static_cast<uint8_t>(b);
}

uint16_t ReadU16(std::istream& is)
{
    char b[2] = {};
    is.read(b, 2);
    return static_cast<uint16_t>(static_cast<uint8_t>(b[0])) |
           (static_cast<uint16_t>(static_cast<uint8_t>(b[1])) << 8);
}

uint32_t ReadU32(std::istream& is)
{
    char b[4] = {};
    is.read(b, 4);
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        v |= static_cast<uint32_t>(static_cast<uint8_t>(b[i])) << (i * 8);
    }
    return v;
}

uint64_t ReadU64(std::istream& is)
{
    char b[8] = {};
    is.read(b, 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(static_cast<uint8_t>(b[i])) << (i * 8);
    }
    return v;
}

int64_t ReadI64(std::istream& is)
{
    return static_cast<int64_t>(ReadU64(is));
}

// ----------------------------------------------------------------------------
// CNetAddr stream adapters
// ----------------------------------------------------------------------------
// CNetAddr's templated Serialize/Unserialize takes a Stream with .read/.write.
// Adapt std::istream/std::ostream to satisfy that contract — gets us proper
// network detection (DetectNetwork is called inside CNetAddr::Unserialize)
// without re-implementing the IPv4-mapped-prefix check here.

struct StreamWriter {
    std::ostream& os;
    void write(const char* data, size_t len) { os.write(data, len); }
};

struct StreamReader {
    std::istream& is;
    void read(char* data, size_t len) { is.read(data, len); }
};

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
//
// Deliberate divergence from upstream (Cursor review Q1, 2026-04-26): the
// "tried in the last minute" branch adds an explicit `now_secs >= last_try_secs`
// guard. Upstream's chrono-typed comparison (`now - m_last_try <= 1min`) on a
// future-timestamped entry yields a NEGATIVE chrono::duration which compares
// less-than-or-equal-to 1min, so future entries are NOT terrible — same end
// state as ours. The guard is defensive: makes intent explicit at the cost of
// one extra compare. If a clock jumps backward and stamps `last_try_secs`
// into the future, both implementations protect the entry; ours just makes
// the protection visible in source. Not a behavioral change — documentation
// of an existing semantic.
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

// Per-entry binary layout (59 bytes total — see CAddrMan_v2::Save format spec):
//
//   [4 bytes]  addr.time          uint32 LE
//   [8 bytes]  addr.services      uint64 LE
//   [16 bytes] addr.ip            raw IPv6 (IPv4-mapped if applicable)
//   [2 bytes]  addr.port          uint16 LE
//   [16 bytes] source             raw IPv6 (network detected on read)
//   [8 bytes]  last_success_secs  int64 LE
//   [4 bytes]  n_attempts         int32 LE (sign-extended via uint32 cast)
//   [1 byte]   in_tried           bool flag (0 or 1)
//
// Memory-only fields (last_try_secs, last_count_attempt_secs, n_ref_count,
// random_pos) are NOT persisted; they reset on Load.
void AddrInfo::SerializeTo(std::ostream& os) const
{
    WriteU32(os, addr.time);
    WriteU64(os, addr.services);
    os.write(reinterpret_cast<const char*>(addr.ip), 16);
    WriteU16(os, addr.port);
    // CNetAddr is just 16 raw bytes; net is detected on read.
    os.write(reinterpret_cast<const char*>(source.GetAddrBytes()), 16);
    WriteI64(os, last_success_secs);
    WriteU32(os, static_cast<uint32_t>(n_attempts));
    WriteU8(os, in_tried ? 1 : 0);
}

void AddrInfo::DeserializeFrom(std::istream& is)
{
    addr.time = ReadU32(is);
    addr.services = ReadU64(is);
    is.read(reinterpret_cast<char*>(addr.ip), 16);
    addr.port = ReadU16(is);

    // Use CNetAddr's templated Unserialize so DetectNetwork populates m_net
    // correctly (handles IPv4-mapped prefix detection).
    StreamReader r{is};
    source.Unserialize(r);

    last_success_secs = ReadI64(is);
    n_attempts = static_cast<int>(ReadU32(is));
    in_tried = (ReadU8(is) != 0);

    // Memory-only fields — reset to defaults; bucket placement on Load
    // populates n_ref_count and random_pos.
    last_try_secs = 0;
    last_count_attempt_secs = 0;
    n_ref_count = 0;
    random_pos = -1;
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

// Map IAddressManager's OutboundClass onto the binary new-only/either choice
// that Bitcoin Core's Select_ exposes:
//   * Feeler              — exclusively new (unverified) addrs to refresh
//                           freshness signals
//   * FullRelay / BlockRelay / Manual — either table; bucket walk picks
//                           with 50/50 bias when both are populated
//
// Phase 4 PeerManager will refine this dispatch (e.g. BlockRelay may want to
// avoid recently-tried-and-failed entries more aggressively); for Phase 1
// the binary distinction is enough to satisfy IAddressManager's contract.
std::optional<NetProtocol::CAddress> CAddrMan_v2::Select(OutboundClass cls)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    const bool new_only = (cls == OutboundClass::Feeler);
    auto sel = SelectInternal(new_only);
    if (!sel) return std::nullopt;
    return sel->first;
}

// Mirrors upstream's Select_ (addrman.cpp:713-787). Bucket walk with
// chance_factor ramp.
//
// Phase 1 BLOCKER fix (Cursor review 2026-04-26): drain m_tried_collisions
// before the bucket walk. Upstream relies on PeerManager invoking
// ResolveCollisions on a 30s timer; that infrastructure lands in Phase 4/6.
// Until then, every Select call resolves any pending collisions so the
// queue stays bounded by ADDRMAN_SET_TRIED_COLLISION_SIZE and
// test-before-evict actually completes (a queued promotion never stays
// queued forever, which it would have in the dead-code-path version of
// this method).
std::optional<std::pair<NetProtocol::CAddress, int64_t>>
CAddrMan_v2::SelectInternal(bool new_only)
{
    ResolveTriedCollisions();

    if (m_random.empty()) return std::nullopt;
    if (new_only && m_new_count == 0) return std::nullopt;
    if (m_new_count + m_tried_count == 0) return std::nullopt;

    // Decide which table to draw from. 50/50 when both populated; forced if
    // one side is empty or caller asked for new-only.
    bool search_tried;
    if (new_only || m_tried_count == 0) {
        search_tried = false;
    } else if (m_new_count == 0) {
        search_tried = true;
    } else {
        search_tried = (std::uniform_int_distribution<int>(0, 1)(m_rng) == 1);
    }

    const int bucket_count = search_tried
        ? ADDRMAN_TRIED_BUCKET_COUNT
        : ADDRMAN_NEW_BUCKET_COUNT;

    // chance_factor escalates each rejected candidate so termination is
    // guaranteed: GetChance() ≥ ~0.000036 (worst case), and 1.2^N grows
    // unbounded. In expectation the loop terminates in <50 iterations.
    double chance_factor = 1.0;

    while (true) {
        const int bucket = std::uniform_int_distribution<int>(0, bucket_count - 1)(m_rng);
        const int initial_pos = std::uniform_int_distribution<int>(0, ADDRMAN_BUCKET_SIZE - 1)(m_rng);

        int pos = 0;
        int node_id = 0;
        int i = 0;
        for (; i < ADDRMAN_BUCKET_SIZE; ++i) {
            pos = (initial_pos + i) % ADDRMAN_BUCKET_SIZE;
            node_id = search_tried
                ? m_tried_buckets[bucket][pos]
                : m_new_buckets[bucket][pos];
            if (node_id != 0) break;
        }

        // Bucket entirely empty — pick a different one.
        if (i == ADDRMAN_BUCKET_SIZE) continue;

        auto info_it = m_info.find(node_id);
        assert(info_it != m_info.end());
        const AddrInfo& info = info_it->second;

        // Probability check: upstream is `randbits<30>() < chance * (1<<30)`.
        // Draws are in [0, 2^30). When `chance >= 1.0` upstream's threshold
        // becomes 2^30 and every draw is accepted. We short-circuit that
        // case first to preserve fidelity — clamping `threshold` to
        // `(1u<<30)-1` (Cursor Q4) would silently reject one in 2^30 draws
        // even at certainty.
        //
        // Below the certainty threshold, the integer cast is well-defined:
        // `accept_p` is non-negative (GetChance ≥ 0; chance_factor ≥ 1 by
        // construction) and clamped < 1.0 here, so the multiply lands in
        // [0, 2^30) and fits uint32_t cleanly.
        const double accept_p = chance_factor * info.GetChance(NowSecs());
        if (accept_p >= 1.0) {
            return std::make_pair(info.addr, info.last_try_secs);
        }
        const uint32_t threshold =
            static_cast<uint32_t>(accept_p * static_cast<double>(1u << 30));
        const uint32_t draw = std::uniform_int_distribution<uint32_t>(
            0, (1u << 30) - 1)(m_rng);

        if (draw < threshold) {
            return std::make_pair(info.addr, info.last_try_secs);
        }

        // Reject — escalate chance_factor and loop.
        chance_factor *= 1.2;
    }
}

// Mirrors upstream's GetAddr_ (addrman.cpp:806-842). Returns a random subset
// of non-terrible addresses for ADDR-message gossip.
//
//   max_count    — hard cap on result size (0 = unlimited).
//   max_pct      — soft cap as % of m_random.size() (0 = unlimited).
//   network_filter — optional Network-as-int; when set, only addrs of that
//                    network are returned.
std::vector<NetProtocol::CAddress> CAddrMan_v2::GetAddresses(
    size_t max_count,
    size_t max_pct,
    std::optional<int> network_filter)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    size_t n_nodes = m_random.size();
    if (max_pct != 0) {
        n_nodes = max_pct * n_nodes / 100;
    }
    if (max_count != 0) {
        n_nodes = std::min(n_nodes, max_count);
    }

    const int64_t now = NowSecs();
    std::vector<NetProtocol::CAddress> out;
    out.reserve(n_nodes);

    // Fisher-Yates partial shuffle: walk forward through m_random, swap each
    // position with a random remaining slot, take the prefix. This produces
    // an unbiased random sample of size n_nodes — same trick as upstream.
    for (size_t n = 0; n < m_random.size(); ++n) {
        if (out.size() >= n_nodes) break;

        const size_t pick = std::uniform_int_distribution<size_t>(
            n, m_random.size() - 1)(m_rng);
        SwapRandom(static_cast<unsigned int>(n),
                   static_cast<unsigned int>(pick));

        auto info_it = m_info.find(m_random[n]);
        assert(info_it != m_info.end());
        const AddrInfo& info = info_it->second;

        if (network_filter.has_value()) {
            const int net = static_cast<int>(ToNetAddr(info.addr).GetNetwork());
            if (net != *network_filter) continue;
        }

        if (info.IsTerrible(now)) continue;

        out.push_back(info.addr);
    }

    return out;
}

// peers.dat format (v2, ADDRMAN_V2_FORMAT_VERSION = 1):
//
//   [1 byte]   format version
//   [32 bytes] m_bucket_secret (raw, restored verbatim so bucket math is
//              deterministic across restarts)
//   [8 bytes]  m_last_good_secs (int64 LE)
//   [4 bytes]  count of entries (uint32 LE)
//   [count × 59 bytes] entries, each via AddrInfo::SerializeTo
//
// Buckets are NOT persisted — Load rebuilds them from each entry's
// (addr, source, in_tried) state by re-running GetTriedBucket /
// GetNewBucket / GetBucketPosition under the restored secret. KISS:
// avoids serializing the bucket grid (~320KB) and keeps the format
// resilient to bucket-arithmetic changes.
//
// Atomic-write discipline: write to peers.dat.new, close, then rename.
// On Windows, rename does not replace an existing file, so we remove
// the old peers.dat first (mirrors src/net/addrman.cpp:684-733).
bool CAddrMan_v2::Save()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_data_path.empty()) {
        // Caller never set a data path — silently skip rather than fail
        // (lets headless tests reuse CAddrMan_v2 without filesystem setup).
        return true;
    }

    const std::string tmp_path = m_data_path + ".new";

    try {
        std::ofstream f(tmp_path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;

        // Header.
        WriteU8(f, ADDRMAN_V2_FORMAT_VERSION);
        f.write(reinterpret_cast<const char*>(m_bucket_secret.data), 32);
        WriteI64(f, m_last_good_secs);
        WriteU32(f, static_cast<uint32_t>(m_info.size()));

        // Entries — iteration order doesn't matter; Load rebuilds buckets.
        for (const auto& kv : m_info) {
            kv.second.SerializeTo(f);
        }

        if (!f.good()) {
            f.close();
            (void)std::remove(tmp_path.c_str());
            return false;
        }
        f.close();

        // Atomic-rename dance.
#ifdef _WIN32
        if (std::remove(m_data_path.c_str()) != 0) {
            DWORD err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
                std::cerr << "[AddrMan_v2] Warning: failed to remove old "
                          << m_data_path << " (err=" << err << ")\n";
                // Fall through — rename may still succeed if file was
                // already gone underneath us.
            }
        }
#endif
        if (std::rename(tmp_path.c_str(), m_data_path.c_str()) != 0) {
            (void)std::remove(tmp_path.c_str());
            return false;
        }
        return true;

    } catch (...) {
        (void)std::remove(tmp_path.c_str());
        return false;
    }
}

bool CAddrMan_v2::Load()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_data_path.empty()) {
        // No file path configured — caller wants in-memory operation.
        return true;
    }

    std::ifstream f(m_data_path, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        // File missing is NOT an error — empty AddrMan + DNS seeds will
        // bootstrap. Caller distinguishes load-failed-fatally from load-
        // empty-OK by inspecting Size() afterward.
        return true;
    }

    try {
        // Format version.
        uint8_t version = ReadU8(f);
        if (!f.good()) return false;
        if (version != ADDRMAN_V2_FORMAT_VERSION) {
            std::cerr << "[AddrMan_v2] Unknown format version "
                      << static_cast<int>(version)
                      << " in " << m_data_path << "; ignoring\n";
            return false;
        }

        // Bucket secret — restored verbatim so bucket math reproduces.
        f.read(reinterpret_cast<char*>(m_bucket_secret.data), 32);

        m_last_good_secs = ReadI64(f);
        uint32_t count = ReadU32(f);
        if (!f.good()) return false;

        // Sanity bound: combined-table capacity is 1024×64 + 256×64 = 81920.
        // Anything materially larger is a corruption signal.
        constexpr uint32_t kMaxEntries = 100000;
        if (count > kMaxEntries) {
            std::cerr << "[AddrMan_v2] Refusing to load: count=" << count
                      << " exceeds sanity bound " << kMaxEntries << "\n";
            return false;
        }

        // Read all entries; place each into its canonical bucket. Drop any
        // entry that fails to place (collides) — same as upstream's nLost
        // accounting at addrman.cpp:294-314.
        for (uint32_t i = 0; i < count; ++i) {
            AddrInfo info;
            info.DeserializeFrom(f);
            if (!f.good()) return false;

            const CService addr_svc = ToService(info.addr);
            if (!addr_svc.IsRoutable()) continue;  // skip stale unroutables

            const int id = m_next_id++;
            info.random_pos = static_cast<int>(m_random.size());

            const int net = static_cast<int>(ToNetAddr(info.addr).GetNetwork());

            if (info.in_tried) {
                // Tried bucket placement.
                const int b = GetTriedBucket(m_bucket_secret, addr_svc);
                const int p = GetBucketPosition(m_bucket_secret, /*fNew=*/false,
                                                b, addr_svc);
                if (m_tried_buckets[b][p] != 0) continue;  // collision: drop
                m_tried_buckets[b][p] = id;
                ++m_tried_count;
                ++m_network_counts[net].n_tried;
            } else {
                // New bucket placement (single-ref, primary source).
                const int b = GetNewBucket(m_bucket_secret, addr_svc, info.source);
                const int p = GetBucketPosition(m_bucket_secret, /*fNew=*/true,
                                                b, addr_svc);
                if (m_new_buckets[b][p] != 0) continue;
                m_new_buckets[b][p] = id;
                info.n_ref_count = 1;
                ++m_new_count;
                ++m_network_counts[net].n_new;
            }

            m_info[id] = info;
            m_id_by_addr[addr_svc] = id;
            m_random.push_back(id);
        }

        return true;

    } catch (...) {
        // Reset state on any throw — better to start fresh than partial.
        m_info.clear();
        m_id_by_addr.clear();
        m_random.clear();
        m_tried_count = 0;
        m_new_count = 0;
        m_network_counts.clear();
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
        return false;
    }
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

size_t CAddrMan_v2::TriedCollisionsSizeForTest() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tried_collisions.size();
}

}  // namespace dilithion::net::port
