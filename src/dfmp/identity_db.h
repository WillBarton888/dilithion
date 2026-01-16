// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DFMP_IDENTITY_DB_H
#define DILITHION_DFMP_IDENTITY_DB_H

/**
 * DFMP Identity Database
 *
 * Persistent storage for miner identity first-seen heights.
 * Uses LevelDB for durability across node restarts.
 *
 * Key format: "dfmp:" + identity hex (45 bytes total)
 * Value format: 4-byte little-endian height
 */

#include <dfmp/dfmp.h>
#include <leveldb/db.h>

#include <memory>
#include <mutex>
#include <map>
#include <string>

namespace DFMP {

/**
 * LevelDB-backed storage for identity first-seen heights
 *
 * Thread-safe: Protected by internal mutex.
 * Cached: Hot identities cached in memory for performance.
 */
class CIdentityDB {
private:
    /** LevelDB database handle */
    std::unique_ptr<leveldb::DB> m_db;

    /** Mutex for thread safety */
    mutable std::mutex m_mutex;

    /** In-memory cache: identity -> first-seen height */
    mutable std::map<Identity, int> m_cache;

    /** Maximum cache size */
    static const size_t MAX_CACHE_SIZE = 10000;

    /** Database path */
    std::string m_path;

    /** Key prefix for identity entries */
    static const std::string KEY_PREFIX;

    /** Build database key from identity */
    std::string MakeKey(const Identity& identity) const;

    /** Parse identity from database key */
    bool ParseKey(const std::string& key, Identity& identity) const;

    /** Evict oldest entries from cache if over limit */
    void EvictCacheIfNeeded() const;

public:
    CIdentityDB();
    ~CIdentityDB();

    // Prevent copying
    CIdentityDB(const CIdentityDB&) = delete;
    CIdentityDB& operator=(const CIdentityDB&) = delete;

    /**
     * Open the identity database
     *
     * @param path Directory path for database files
     * @return true if opened successfully
     */
    bool Open(const std::string& path);

    /**
     * Close the database
     */
    void Close();

    /**
     * Check if database is open
     */
    bool IsOpen() const;

    /**
     * Get first-seen height for an identity
     *
     * @param identity Miner identity to query
     * @return First-seen block height, or -1 if not found
     */
    int GetFirstSeen(const Identity& identity) const;

    /**
     * Set first-seen height for a new identity
     *
     * Does nothing if identity already exists (first-seen is immutable).
     *
     * @param identity Miner identity
     * @param height Block height where identity first appeared
     * @return true if stored (new identity), false if already existed
     */
    bool SetFirstSeen(const Identity& identity, int height);

    /**
     * Check if an identity exists in the database
     *
     * @param identity Miner identity to check
     * @return true if identity has been seen before
     */
    bool Exists(const Identity& identity) const;

    /**
     * Get count of known identities (for stats)
     *
     * Note: This may be slow as it counts all entries.
     */
    size_t GetIdentityCount() const;

    /**
     * Clear all data (for testing)
     */
    void Clear();
};

} // namespace DFMP

#endif // DILITHION_DFMP_IDENTITY_DB_H
