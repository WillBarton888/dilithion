// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/identity_db.h>

#include <leveldb/write_batch.h>
#include <cstring>
#include <iostream>

namespace DFMP {

// Key prefix for identity entries
const std::string CIdentityDB::KEY_PREFIX = "dfmp:";

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

    // Delete all DFMP entries
    leveldb::WriteBatch batch;
    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, KEY_PREFIX.size()) == KEY_PREFIX) {
            batch.Delete(key);
        }
    }

    m_db->Write(leveldb::WriteOptions(), &batch);
    m_cache.clear();
}

} // namespace DFMP
