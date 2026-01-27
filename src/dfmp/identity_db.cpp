// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/identity_db.h>
#include <dfmp/mik.h>

#include <leveldb/write_batch.h>
#include <cstring>
#include <iostream>

namespace DFMP {

// Key prefix for identity first-seen height entries
const std::string CIdentityDB::KEY_PREFIX = "dfmp:";

// Key prefix for MIK public key entries (v2.0)
const std::string CIdentityDB::MIK_PUBKEY_PREFIX = "mikpk:";

CIdentityDB::CIdentityDB() : m_db(nullptr) {}

CIdentityDB::~CIdentityDB() {
    Close();
}

std::string CIdentityDB::MakeKey(const Identity& identity) const {
    return KEY_PREFIX + identity.GetHex();
}

bool CIdentityDB::ParseKey(const std::string& key, Identity& identity) const {
    if (key.size() != KEY_PREFIX.size() + 40) {
        return false;
    }
    if (key.substr(0, KEY_PREFIX.size()) != KEY_PREFIX) {
        return false;
    }
    return identity.SetHex(key.substr(KEY_PREFIX.size()));
}

void CIdentityDB::EvictCacheIfNeeded() const {
    // Simple eviction: clear half the cache when full
    if (m_cache.size() > MAX_CACHE_SIZE) {
        size_t toRemove = m_cache.size() / 2;
        auto it = m_cache.begin();
        while (toRemove > 0 && it != m_cache.end()) {
            it = m_cache.erase(it);
            toRemove--;
        }
    }
}

std::string CIdentityDB::MakeMIKPubkeyKey(const Identity& identity) const {
    return MIK_PUBKEY_PREFIX + identity.GetHex();
}

void CIdentityDB::EvictMIKCacheIfNeeded() const {
    // Simple eviction: clear half the cache when full
    // Note: MIK pubkeys are large (1952 bytes), so keep cache small
    if (m_mikPubkeyCache.size() > MAX_MIK_CACHE_SIZE) {
        size_t toRemove = m_mikPubkeyCache.size() / 2;
        auto it = m_mikPubkeyCache.begin();
        while (toRemove > 0 && it != m_mikPubkeyCache.end()) {
            it = m_mikPubkeyCache.erase(it);
            toRemove--;
        }
    }
}

bool CIdentityDB::Open(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_db) {
        return true;  // Already open
    }

    m_path = path;

    leveldb::Options options;
    options.create_if_missing = true;
    options.write_buffer_size = 4 * 1024 * 1024;  // 4MB write buffer
    options.max_open_files = 100;
    // Note: LevelDB uses default block cache if not specified

    leveldb::DB* db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &db);

    if (!status.ok()) {
        std::cerr << "[DFMP] Failed to open identity database: " << status.ToString() << std::endl;
        return false;
    }

    m_db.reset(db);
    m_cache.clear();

    std::cout << "[DFMP] Identity database opened: " << path << std::endl;
    return true;
}

void CIdentityDB::Close() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_db) {
        m_db.reset();
        m_cache.clear();
        m_mikPubkeyCache.clear();
        std::cout << "[DFMP] Identity database closed" << std::endl;
    }
}

bool CIdentityDB::IsOpen() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_db != nullptr;
}

int CIdentityDB::GetFirstSeen(const Identity& identity) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return -1;
    }

    // Check cache first
    auto cacheIt = m_cache.find(identity);
    if (cacheIt != m_cache.end()) {
        return cacheIt->second;
    }

    // Query database
    std::string key = MakeKey(identity);
    std::string value;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), key, &value);

    if (!status.ok()) {
        return -1;  // Not found
    }

    // Parse height (4-byte little-endian)
    if (value.size() != 4) {
        return -1;  // Invalid data
    }

    int32_t height = 0;
    std::memcpy(&height, value.data(), 4);

    // Add to cache
    EvictCacheIfNeeded();
    m_cache[identity] = height;

    return height;
}

bool CIdentityDB::SetFirstSeen(const Identity& identity, int height) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    // Check if already exists (in cache or DB)
    auto cacheIt = m_cache.find(identity);
    if (cacheIt != m_cache.end()) {
        return false;  // Already exists
    }

    std::string key = MakeKey(identity);
    std::string existingValue;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), key, &existingValue);
    if (status.ok()) {
        // Already exists in DB, add to cache
        int32_t existingHeight = 0;
        if (existingValue.size() == 4) {
            std::memcpy(&existingHeight, existingValue.data(), 4);
        }
        EvictCacheIfNeeded();
        m_cache[identity] = existingHeight;
        return false;  // Already exists
    }

    // Store new identity
    int32_t heightLE = static_cast<int32_t>(height);
    std::string value(reinterpret_cast<char*>(&heightLE), 4);

    leveldb::WriteOptions writeOpts;
    writeOpts.sync = true;  // Ensure durability

    status = m_db->Put(writeOpts, key, value);

    if (!status.ok()) {
        std::cerr << "[DFMP] Failed to write identity: " << status.ToString() << std::endl;
        return false;
    }

    // Add to cache
    EvictCacheIfNeeded();
    m_cache[identity] = height;

    return true;
}

bool CIdentityDB::Exists(const Identity& identity) const {
    return GetFirstSeen(identity) >= 0;
}

size_t CIdentityDB::GetIdentityCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return 0;
    }

    size_t count = 0;
    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, KEY_PREFIX.size()) == KEY_PREFIX) {
            count++;
        }
    }

    return count;
}

void CIdentityDB::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return;
    }

    // Delete all DFMP entries (both first-seen and MIK pubkey)
    leveldb::WriteBatch batch;
    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, KEY_PREFIX.size()) == KEY_PREFIX ||
            key.substr(0, MIK_PUBKEY_PREFIX.size()) == MIK_PUBKEY_PREFIX) {
            batch.Delete(key);
        }
    }

    m_db->Write(leveldb::WriteOptions(), &batch);
    m_cache.clear();
    m_mikPubkeyCache.clear();
}

// ============================================================================
// MIK Public Key Storage (DFMP v2.0)
// ============================================================================

bool CIdentityDB::SetMIKPubKey(const Identity& identity, const std::vector<uint8_t>& pubkey) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    // Validate pubkey size
    if (pubkey.size() != MIK_PUBKEY_SIZE) {
        std::cerr << "[DFMP] Invalid MIK pubkey size: " << pubkey.size()
                  << " (expected " << MIK_PUBKEY_SIZE << ")" << std::endl;
        return false;
    }

    // Verify identity matches pubkey
    Identity derivedIdentity = DeriveIdentityFromMIK(pubkey);
    if (derivedIdentity != identity) {
        std::cerr << "[DFMP] MIK pubkey does not match identity" << std::endl;
        return false;
    }

    // Check if already exists (in cache or DB)
    auto cacheIt = m_mikPubkeyCache.find(identity);
    if (cacheIt != m_mikPubkeyCache.end()) {
        return false;  // Already exists
    }

    std::string key = MakeMIKPubkeyKey(identity);
    std::string existingValue;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), key, &existingValue);
    if (status.ok()) {
        // Already exists in DB, add to cache
        std::vector<uint8_t> cachedPubkey(existingValue.begin(), existingValue.end());
        EvictMIKCacheIfNeeded();
        m_mikPubkeyCache[identity] = std::move(cachedPubkey);  // Move instead of copy (perf fix)
        return false;  // Already exists
    }

    // Store new MIK pubkey
    std::string value(reinterpret_cast<const char*>(pubkey.data()), pubkey.size());

    leveldb::WriteOptions writeOpts;
    writeOpts.sync = true;  // Ensure durability

    status = m_db->Put(writeOpts, key, value);

    if (!status.ok()) {
        std::cerr << "[DFMP] Failed to write MIK pubkey: " << status.ToString() << std::endl;
        return false;
    }

    // Add to cache
    EvictMIKCacheIfNeeded();
    m_mikPubkeyCache[identity] = pubkey;

    std::cout << "[DFMP] Registered MIK identity: " << identity.GetHex() << std::endl;
    return true;
}

bool CIdentityDB::GetMIKPubKey(const Identity& identity, std::vector<uint8_t>& pubkey) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    // Check cache first
    auto cacheIt = m_mikPubkeyCache.find(identity);
    if (cacheIt != m_mikPubkeyCache.end()) {
        pubkey = cacheIt->second;
        return true;
    }

    // Query database
    std::string key = MakeMIKPubkeyKey(identity);
    std::string value;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), key, &value);

    if (!status.ok()) {
        return false;  // Not found
    }

    // Validate size
    if (value.size() != MIK_PUBKEY_SIZE) {
        std::cerr << "[DFMP] Corrupted MIK pubkey in DB: size=" << value.size() << std::endl;
        return false;
    }

    // Copy to output
    pubkey.assign(value.begin(), value.end());

    // Add to cache
    EvictMIKCacheIfNeeded();
    m_mikPubkeyCache[identity] = pubkey;

    return true;
}

bool CIdentityDB::HasMIKPubKey(const Identity& identity) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    // Check cache first
    if (m_mikPubkeyCache.find(identity) != m_mikPubkeyCache.end()) {
        return true;
    }

    // Query database
    std::string key = MakeMIKPubkeyKey(identity);
    std::string value;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), key, &value);
    return status.ok();
}

} // namespace DFMP
