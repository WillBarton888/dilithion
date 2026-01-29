// Copyright (c) 2012-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DILITHION_NET_ADDRMAN_H
#define DILITHION_NET_ADDRMAN_H

#include <net/netaddress.h>
#include <crypto/sha3.h>
#include <primitives/block.h>

#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <random>
#include <mutex>
#include <optional>
#include <chrono>

/**
 * @file addrman.h
 * @brief Address Manager - ported from Bitcoin Core
 *
 * Manages peer addresses with eclipse attack protection using:
 * - Two-table system (new/tried) with bucket distribution
 * - Cryptographic bucket assignment using SHA3-256
 * - Network group diversity (/16 prefix for IPv4)
 * - Source attribution tracking
 * - Time-based protections
 *
 * This is critical infrastructure for mainnet security.
 */

// Forward declarations
class CAddrMan;

/**
 * @struct CNetworkAddr
 * @brief Extended network address with metadata
 *
 * Extends CService with timestamp and service flags for P2P communication.
 * Named CNetworkAddr to avoid collision with wallet's CAddress.
 */
struct CNetworkAddr : public CService {
    uint64_t nServices;      ///< Service flags (NODE_NETWORK, etc.)
    int64_t nTime;           ///< Last seen timestamp (seconds since epoch)

    CNetworkAddr() : CService(), nServices(0), nTime(0) {}
    CNetworkAddr(const CService& service, uint64_t services = 0, int64_t time = 0)
        : CService(service), nServices(services), nTime(time) {}

    // Serialization
    template<typename Stream>
    void Serialize(Stream& s) const {
        // Version byte for future compatibility
        uint8_t version = 1;
        s.write(reinterpret_cast<const char*>(&version), 1);

        // Time
        uint32_t nTimeLow = nTime & 0xFFFFFFFF;
        s.write(reinterpret_cast<const char*>(&nTimeLow), 4);

        // Services
        s.write(reinterpret_cast<const char*>(&nServices), 8);

        // Base address
        CService::Serialize(s);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        uint8_t version;
        s.read(reinterpret_cast<char*>(&version), 1);

        uint32_t nTimeLow;
        s.read(reinterpret_cast<char*>(&nTimeLow), 4);
        nTime = nTimeLow;

        s.read(reinterpret_cast<char*>(&nServices), 8);

        CService::Unserialize(s);
    }
};

/**
 * @class CAddrInfo
 * @brief Extended address entry with tracking metadata
 *
 * Stores additional information for address management:
 * - Source address (who told us about this peer)
 * - Connection attempt tracking
 * - Success/failure history
 * - Random position for bucket assignment
 */
class CAddrInfo : public CNetworkAddr {
public:
    //! Where knowledge about this address first came from
    CNetAddr source;

    //! Last successful connection timestamp
    int64_t nLastSuccess;

    //! Connection attempts since last success
    int nAttempts;

    //! Reference count in new table buckets
    int nRefCount;

    //! Is this entry in the tried table?
    bool fInTried;

    //! Random position for consistent bucket assignment
    int nRandomPos;

    //! Last connection attempt timestamp
    int64_t nLastTry;

    //! Last counted attempt timestamp (for retry logic)
    int64_t nLastCountAttempt;

    CAddrInfo()
        : CNetworkAddr(),
          nLastSuccess(0),
          nAttempts(0),
          nRefCount(0),
          fInTried(false),
          nRandomPos(-1),
          nLastTry(0),
          nLastCountAttempt(0) {}

    CAddrInfo(const CNetworkAddr& addr, const CNetAddr& src)
        : CNetworkAddr(addr),
          source(src),
          nLastSuccess(0),
          nAttempts(0),
          nRefCount(0),
          fInTried(false),
          nRandomPos(-1),
          nLastTry(0),
          nLastCountAttempt(0) {}

    /**
     * @brief Calculate chance of being selected
     *
     * Addresses with more recent success and fewer attempts get higher priority.
     *
     * @param nNow Current timestamp
     * @return Relative chance (0-1) of selection
     */
    double GetChance(int64_t nNow) const;

    /**
     * @brief Check if address is "terrible" and should be evicted
     *
     * An address is terrible if:
     * - Last attempt was in last minute AND never succeeded
     * - Too many consecutive failures
     * - Last success too long ago
     */
    bool IsTerrible(int64_t nNow) const;

    // Serialization
    template<typename Stream>
    void Serialize(Stream& s) const {
        CNetworkAddr::Serialize(s);
        source.Serialize(s);

        s.write(reinterpret_cast<const char*>(&nLastSuccess), 8);
        s.write(reinterpret_cast<const char*>(&nAttempts), 4);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        CNetworkAddr::Unserialize(s);
        source.Unserialize(s);

        s.read(reinterpret_cast<char*>(&nLastSuccess), 8);
        s.read(reinterpret_cast<char*>(&nAttempts), 4);

        nRefCount = 0;
        fInTried = false;
        nRandomPos = -1;
        nLastTry = 0;
        nLastCountAttempt = 0;
    }
};

/**
 * @class CAddrMan
 * @brief Stochastic address manager - Bitcoin Core's eclipse attack protection
 *
 * Key security features:
 *
 * 1. **Two-table system**:
 *    - New table: Addresses we learned about but haven't connected to
 *    - Tried table: Addresses we successfully connected to
 *
 * 2. **Bucket system**:
 *    - New table: 1024 buckets × 64 entries = 65,536 slots
 *    - Tried table: 256 buckets × 64 entries = 16,384 slots
 *
 * 3. **Cryptographic bucket assignment**:
 *    - Uses SHA3-256 with secret 256-bit key
 *    - Bucket = Hash(key, address, source) mod bucket_count
 *    - Prevents attacker from predicting bucket placement
 *
 * 4. **Network group diversity**:
 *    - Each bucket limits entries from same /16 network
 *    - Prevents eclipse attack from single AS
 *
 * 5. **Source attribution**:
 *    - Tracks who told us about each address
 *    - Same source can only fill limited buckets
 */
class CAddrMan {
public:
    CAddrMan();
    ~CAddrMan() = default;

    // Disable copy
    CAddrMan(const CAddrMan&) = delete;
    CAddrMan& operator=(const CAddrMan&) = delete;

    /**
     * @brief Add addresses to the address manager
     *
     * @param vAddr Vector of addresses to add
     * @param source Who told us about these addresses
     * @param nTimePenalty Penalty to subtract from timestamp (default 0)
     * @return Number of addresses actually added
     */
    int Add(const std::vector<CNetworkAddr>& vAddr, const CNetAddr& source, int64_t nTimePenalty = 0);

    /**
     * @brief Add a single address
     */
    bool Add(const CNetworkAddr& addr, const CNetAddr& source, int64_t nTimePenalty = 0);

    /**
     * @brief Mark an address as successfully connected
     *
     * Moves address from new to tried table.
     *
     * @param addr Address that connected successfully
     * @param nTime Connection timestamp
     */
    void Good(const CService& addr, int64_t nTime = 0);

    /**
     * @brief Mark a connection attempt
     *
     * @param addr Address we attempted to connect to
     * @param fCountFailure If true, increment failure counter
     * @param nTime Attempt timestamp
     */
    void Attempt(const CService& addr, bool fCountFailure, int64_t nTime = 0);

    /**
     * @brief Select an address to connect to
     *
     * Uses weighted random selection favoring:
     * - Addresses not recently attempted
     * - Addresses with successful history
     *
     * @param newOnly If true, only select from new table
     * @return Selected address, or empty if none available
     */
    std::pair<CNetworkAddr, int64_t> Select(bool newOnly = false) const;

    /**
     * @brief Get addresses for sharing with peers (ADDR message)
     *
     * @param maxAddresses Maximum addresses to return
     * @param maxPct Maximum percentage of addresses (0-100)
     * @return Vector of addresses
     */
    std::vector<CNetworkAddr> GetAddr(size_t maxAddresses, size_t maxPct) const;

    /**
     * @brief Get total number of addresses
     */
    size_t Size() const;

    /**
     * @brief Get number of unique addresses
     */
    size_t GetUniqueAddressCount() const { return Size(); }

    /**
     * @brief Check if empty
     */
    bool Empty() const { return Size() == 0; }

    /**
     * @brief Clear all addresses
     */
    void Clear();

    /**
     * @brief Set the random key (for testing)
     */
    void SetKey(const uint256& key);

    // Persistence
    /**
     * @brief Serialize to stream (for peers.dat)
     */
    template<typename Stream>
    void Serialize(Stream& s) const;

    /**
     * @brief Deserialize from stream
     */
    template<typename Stream>
    void Unserialize(Stream& s);

    /**
     * @brief Save address database to file
     *
     * @param path Full path to file (e.g., ~/.dilithion/peers.dat)
     * @return true on success
     */
    bool SaveToFile(const std::string& path) const;

    /**
     * @brief Load address database from file
     *
     * @param path Full path to file
     * @return true on success (returns true with empty AddrMan if file doesn't exist)
     */
    bool LoadFromFile(const std::string& path);

    // Statistics
    /**
     * @brief Get counts for each table
     */
    void GetStats(int& nNew, int& nTried) const;

    /**
     * @brief Get detailed bucket statistics
     */
    std::string GetBucketStats() const;

private:
    // Constants from Bitcoin Core (must be declared before arrays that use them)
    static constexpr int ADDRMAN_TRIED_BUCKET_COUNT = 256;      ///< Number of tried buckets
    static constexpr int ADDRMAN_NEW_BUCKET_COUNT = 1024;       ///< Number of new buckets
    static constexpr int ADDRMAN_BUCKET_SIZE = 64;              ///< Entries per bucket
    static constexpr int ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8;   ///< Tried buckets per group
    static constexpr int ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64;  ///< New buckets per source
    static constexpr int ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8;   ///< New buckets per address

public:
    // Public constants needed by CAddrInfo
    static constexpr int64_t ADDRMAN_HORIZON_DAYS = 30;         ///< Max age in days
    static constexpr int ADDRMAN_RETRIES = 3;                   ///< Retries before penalty
    static constexpr int ADDRMAN_MAX_FAILURES = 10;             ///< Max failures before removal
    static constexpr int64_t ADDRMAN_MIN_FAIL_DAYS = 7;         ///< Min days before failure counted
    static constexpr int ADDRMAN_SET_TRIED_COLLISION_SIZE = 10; ///< Collision set size

private:
    //! Critical section for thread safety
    mutable std::mutex cs;

    //! Secret key for bucket assignment (256-bit)
    uint256 nKey;

    //! Random number generator
    mutable std::mt19937_64 insecure_rand;

    //! Map of addresses (id -> info)
    std::map<int, CAddrInfo> mapInfo;

    //! Map of address to id
    std::map<CService, int> mapAddr;

    //! Random ordering of all addresses
    std::vector<int> vRandom;

    //! Next ID to assign
    int nIdCount;

    /**
     * @brief New table buckets
     *
     * Table of buckets for addresses we've learned about but not connected to.
     * Each bucket has ADDRMAN_BUCKET_SIZE slots.
     * Bucket assignment: Hash(key, group, source_group) mod ADDRMAN_NEW_BUCKET_COUNT
     */
    int vvNew[ADDRMAN_NEW_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE];

    //! Count of entries in new table
    int nNew;

    /**
     * @brief Tried table buckets
     *
     * Table of buckets for addresses we've successfully connected to.
     * Each bucket has ADDRMAN_BUCKET_SIZE slots.
     * Bucket assignment: Hash(key, group) mod ADDRMAN_TRIED_BUCKET_COUNT
     */
    int vvTried[ADDRMAN_TRIED_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE];

    //! Count of entries in tried table
    int nTried;

    //! Number of "checked" entries (for deterministic ADDR)
    int nChecked;

    // Internal methods

    /**
     * @brief Clear all addresses (assumes lock is already held)
     * Used internally by Clear() and Unserialize()
     */
    void ClearLocked();

    /**
     * @brief Find an address in the map
     * @return Pointer to CAddrInfo or nullptr
     */
    CAddrInfo* Find(const CService& addr);
    const CAddrInfo* Find(const CService& addr) const;

    /**
     * @brief Create a new entry
     * @return ID of new entry, or -1 on failure
     */
    int Create(const CNetworkAddr& addr, const CNetAddr& source, int* pnId = nullptr);

    /**
     * @brief Swap two entries in random vector
     */
    void SwapRandom(int nRandomPos1, int nRandomPos2);

    /**
     * @brief Remove an entry
     */
    void Delete(int nId);

    /**
     * @brief Clear a position in new table
     */
    void ClearNew(int nUBucket, int nUBucketPos);

    /**
     * @brief Move an entry to tried table
     */
    void MakeTried(CAddrInfo& info, int nId);

    /**
     * @brief Calculate bucket for address in new table
     */
    int GetNewBucket(const CNetAddr& addr, const CNetAddr& source) const;

    /**
     * @brief Calculate bucket position within bucket
     */
    int GetBucketPosition(const CNetAddr& addr, bool fNew, int nBucket) const;

    /**
     * @brief Calculate bucket for address in tried table
     */
    int GetTriedBucket(const CNetAddr& addr) const;

    /**
     * @brief Get current timestamp
     */
    static int64_t GetAdjustedTime();

    /**
     * @brief Check internal consistency (debug)
     */
    void Check() const;
};

// Serialization format version
static constexpr uint8_t ADDRMAN_SERIALIZE_VERSION = 1;

template<typename Stream>
void CAddrMan::Serialize(Stream& s) const {
    std::lock_guard<std::mutex> lock(cs);

    // Format version
    uint8_t version = ADDRMAN_SERIALIZE_VERSION;
    s.write(reinterpret_cast<const char*>(&version), 1);

    // Key
    s.write(reinterpret_cast<const char*>(nKey.data), 32);

    // Count
    int32_t count = static_cast<int32_t>(mapInfo.size());
    s.write(reinterpret_cast<const char*>(&count), 4);

    // Counts
    s.write(reinterpret_cast<const char*>(&nNew), 4);
    s.write(reinterpret_cast<const char*>(&nTried), 4);

    // Addresses
    int nIds = 0;
    for (const auto& [id, info] : mapInfo) {
        info.Serialize(s);
        nIds++;
    }

    // New table buckets
    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        int nSize = 0;
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            if (vvNew[bucket][i] != -1) nSize++;
        }
        s.write(reinterpret_cast<const char*>(&nSize), 4);

        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            if (vvNew[bucket][i] != -1) {
                int32_t pos = i;
                s.write(reinterpret_cast<const char*>(&pos), 4);

                auto it = mapInfo.find(vvNew[bucket][i]);
                if (it != mapInfo.end()) {
                    it->second.Serialize(s);
                }
            }
        }
    }
}

template<typename Stream>
void CAddrMan::Unserialize(Stream& s) {
    std::lock_guard<std::mutex> lock(cs);

    // Use ClearLocked() since we already hold the lock
    ClearLocked();

    // Format version
    uint8_t version;
    s.read(reinterpret_cast<char*>(&version), 1);

    if (version != ADDRMAN_SERIALIZE_VERSION) {
        // Unknown version, skip loading
        return;
    }

    // Key
    s.read(reinterpret_cast<char*>(nKey.data), 32);

    // Count
    int32_t count;
    s.read(reinterpret_cast<char*>(&count), 4);

    // Counts
    s.read(reinterpret_cast<char*>(&nNew), 4);
    s.read(reinterpret_cast<char*>(&nTried), 4);

    // Read addresses
    for (int32_t i = 0; i < count; i++) {
        CAddrInfo info;
        info.Unserialize(s);

        // Re-add to internal structures
        int nId = nIdCount++;
        mapInfo[nId] = info;
        mapAddr[info] = nId;

        // FIX: Set nRandomPos on mapInfo entry, not the local copy
        // The local 'info' was already copied to mapInfo, so we must update mapInfo directly
        // Otherwise mapInfo[nId].nRandomPos remains -1, causing heap corruption in Delete()
        mapInfo[nId].nRandomPos = static_cast<int>(vRandom.size());
        vRandom.push_back(nId);
    }

    // Note: Bucket assignments are recalculated from addresses
    // This ensures consistency after loading
}

#endif // DILITHION_NET_ADDRMAN_H
