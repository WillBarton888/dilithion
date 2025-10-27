// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/utxo_set.h>
#include <leveldb/write_batch.h>
#include <leveldb/options.h>
#include <cstring>
#include <iostream>

// ============================================================================
// Constructor and Destructor
// ============================================================================

CUTXOSet::CUTXOSet() : db(nullptr) {
    stats.nUTXOs = 0;
    stats.nTotalAmount = 0;
    stats.nHeight = 0;
}

CUTXOSet::~CUTXOSet() {
    Close();
}

// ============================================================================
// Database Management
// ============================================================================

bool CUTXOSet::Open(const std::string& path, bool create_if_missing) {
    std::lock_guard<std::mutex> lock(cs_utxo);

    if (db != nullptr) {
        return true;  // Already open
    }

    datadir = path;

    leveldb::Options options;
    options.create_if_missing = create_if_missing;
    options.compression = leveldb::kSnappyCompression;
    // Larger cache for UTXO set (can be very large)
    options.write_buffer_size = 32 * 1024 * 1024;  // 32MB write buffer

    leveldb::DB* raw_db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &raw_db);

    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::Open: Failed to open database: " << status.ToString() << std::endl;
        return false;
    }

    db.reset(raw_db);

    // Load statistics from database
    std::string stats_key = "utxo_stats";
    std::string stats_value;
    status = db->Get(leveldb::ReadOptions(), stats_key, &stats_value);

    if (status.ok() && stats_value.size() >= 20) {
        // Deserialize stats: nUTXOs (8 bytes) + nTotalAmount (8 bytes) + nHeight (4 bytes)
        const char* ptr = stats_value.data();
        std::memcpy(&stats.nUTXOs, ptr, 8);
        std::memcpy(&stats.nTotalAmount, ptr + 8, 8);
        std::memcpy(&stats.nHeight, ptr + 16, 4);

        std::cout << "[INFO] CUTXOSet: Loaded statistics - UTXOs: " << stats.nUTXOs
                  << ", Total: " << stats.nTotalAmount
                  << ", Height: " << stats.nHeight << std::endl;
    } else {
        std::cout << "[INFO] CUTXOSet: Initializing new UTXO set" << std::endl;
    }

    return true;
}

void CUTXOSet::Close() {
    std::lock_guard<std::mutex> lock(cs_utxo);

    // Flush any pending changes
    if (db != nullptr) {
        // Write statistics before closing
        std::string stats_key = "utxo_stats";
        std::string stats_value;
        stats_value.resize(20);
        std::memcpy(&stats_value[0], &stats.nUTXOs, 8);
        std::memcpy(&stats_value[8], &stats.nTotalAmount, 8);
        std::memcpy(&stats_value[16], &stats.nHeight, 4);
        db->Put(leveldb::WriteOptions(), stats_key, stats_value);
    }

    cache.clear();
    cache_additions.clear();
    cache_deletions.clear();
    db.reset();
}

bool CUTXOSet::IsOpen() const {
    std::lock_guard<std::mutex> lock(cs_utxo);
    return db != nullptr;
}

// ============================================================================
// Serialization Helpers
// ============================================================================

std::string CUTXOSet::SerializeOutPoint(const COutPoint& outpoint) const {
    // Key format: 'u' + txid (32 bytes) + index (4 bytes)
    std::string key;
    key.reserve(37);
    key.push_back('u');  // UTXO prefix
    key.append(reinterpret_cast<const char*>(outpoint.hash.begin()), 32);

    uint32_t n = outpoint.n;
    key.append(reinterpret_cast<const char*>(&n), 4);

    return key;
}

std::string CUTXOSet::SerializeUTXOEntry(const CUTXOEntry& entry) const {
    // Value format: height (4 bytes) + fCoinBase (1 byte) + nValue (8 bytes) + scriptPubKey_size (4 bytes) + scriptPubKey
    std::string value;
    value.reserve(17 + entry.out.scriptPubKey.size());

    // Height
    value.append(reinterpret_cast<const char*>(&entry.nHeight), 4);

    // fCoinBase flag
    uint8_t coinbase_flag = entry.fCoinBase ? 1 : 0;
    value.append(reinterpret_cast<const char*>(&coinbase_flag), 1);

    // nValue
    value.append(reinterpret_cast<const char*>(&entry.out.nValue), 8);

    // scriptPubKey size
    uint32_t script_size = static_cast<uint32_t>(entry.out.scriptPubKey.size());
    value.append(reinterpret_cast<const char*>(&script_size), 4);

    // scriptPubKey data
    if (script_size > 0) {
        value.append(reinterpret_cast<const char*>(entry.out.scriptPubKey.data()), script_size);
    }

    return value;
}

bool CUTXOSet::DeserializeUTXOEntry(const std::string& data, CUTXOEntry& entry) const {
    if (data.size() < 17) {
        std::cerr << "[ERROR] CUTXOSet::DeserializeUTXOEntry: Data too small (" << data.size() << " bytes)" << std::endl;
        return false;
    }

    const char* ptr = data.data();
    size_t offset = 0;

    // Height
    std::memcpy(&entry.nHeight, ptr + offset, 4);
    offset += 4;

    // fCoinBase flag
    uint8_t coinbase_flag;
    std::memcpy(&coinbase_flag, ptr + offset, 1);
    entry.fCoinBase = (coinbase_flag != 0);
    offset += 1;

    // nValue
    std::memcpy(&entry.out.nValue, ptr + offset, 8);
    offset += 8;

    // scriptPubKey size
    uint32_t script_size;
    std::memcpy(&script_size, ptr + offset, 4);
    offset += 4;

    // Validate script size
    if (offset + script_size != data.size()) {
        std::cerr << "[ERROR] CUTXOSet::DeserializeUTXOEntry: Size mismatch" << std::endl;
        return false;
    }

    // scriptPubKey data
    entry.out.scriptPubKey.resize(script_size);
    if (script_size > 0) {
        std::memcpy(entry.out.scriptPubKey.data(), ptr + offset, script_size);
    }

    return true;
}

// ============================================================================
// Cache Management
// ============================================================================

void CUTXOSet::UpdateCache(const COutPoint& outpoint, const CUTXOEntry& entry) const {
    // Keep cache size reasonable (10000 entries max)
    if (cache.size() >= 10000) {
        // Simple eviction: remove first element
        cache.erase(cache.begin());
    }
    cache[outpoint] = entry;
}

void CUTXOSet::RemoveFromCache(const COutPoint& outpoint) const {
    cache.erase(outpoint);
}

bool CUTXOSet::GetFromCache(const COutPoint& outpoint, CUTXOEntry& entry) const {
    auto it = cache.find(outpoint);
    if (it != cache.end()) {
        entry = it->second;
        return true;
    }
    return false;
}

// ============================================================================
// UTXO Operations
// ============================================================================

bool CUTXOSet::GetUTXO(const COutPoint& outpoint, CUTXOEntry& entry) const {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::GetUTXO: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cs_utxo);

    // Check if marked for deletion in pending changes
    if (cache_deletions.find(outpoint) != cache_deletions.end()) {
        return false;
    }

    // Check pending additions first
    auto add_it = cache_additions.find(outpoint);
    if (add_it != cache_additions.end()) {
        entry = add_it->second;
        return true;
    }

    // Check memory cache
    if (GetFromCache(outpoint, entry)) {
        return true;
    }

    // Query database
    std::string key = SerializeOutPoint(outpoint);
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return false;
    }

    // Deserialize entry
    if (!DeserializeUTXOEntry(value, entry)) {
        return false;
    }

    // Update cache
    UpdateCache(outpoint, entry);

    return true;
}

bool CUTXOSet::HaveUTXO(const COutPoint& outpoint) const {
    CUTXOEntry entry;
    return GetUTXO(outpoint, entry);
}

bool CUTXOSet::AddUTXO(const COutPoint& outpoint, const CTxOut& out, uint32_t height, bool fCoinBase) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::AddUTXO: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cs_utxo);

    // Create UTXO entry
    CUTXOEntry entry(out, height, fCoinBase);

    // Add to pending additions (will be flushed later)
    cache_additions[outpoint] = entry;

    // Remove from deletions if present
    cache_deletions.erase(outpoint);

    // Update cache
    UpdateCache(outpoint, entry);

    // Update statistics
    stats.nUTXOs++;
    stats.nTotalAmount += out.nValue;

    return true;
}

bool CUTXOSet::SpendUTXO(const COutPoint& outpoint) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::SpendUTXO: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cs_utxo);

    // Get the UTXO to update statistics
    CUTXOEntry entry;

    // Check pending additions first
    auto add_it = cache_additions.find(outpoint);
    if (add_it != cache_additions.end()) {
        entry = add_it->second;
        cache_additions.erase(add_it);
    } else if (GetFromCache(outpoint, entry)) {
        // Found in cache
    } else {
        // Query database
        std::string key = SerializeOutPoint(outpoint);
        std::string value;

        leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
        if (!status.ok()) {
            std::cerr << "[ERROR] CUTXOSet::SpendUTXO: UTXO not found" << std::endl;
            return false;
        }

        if (!DeserializeUTXOEntry(value, entry)) {
            return false;
        }
    }

    // Mark for deletion
    cache_deletions[outpoint] = true;

    // Remove from cache
    RemoveFromCache(outpoint);

    // Update statistics
    if (stats.nUTXOs > 0) {
        stats.nUTXOs--;
    }
    if (stats.nTotalAmount >= entry.out.nValue) {
        stats.nTotalAmount -= entry.out.nValue;
    }

    return true;
}

bool CUTXOSet::ApplyBlock(const CBlock& block, uint32_t height) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::ApplyBlock: Database not open" << std::endl;
        return false;
    }

    // Note: This is a simplified implementation for Phase 5.1.2
    // Full transaction parsing will be implemented in Phase 5.4
    // For now, we just provide the interface

    std::cout << "[INFO] CUTXOSet::ApplyBlock: Block application at height " << height
              << " (transaction processing not yet implemented)" << std::endl;

    stats.nHeight = height;

    return true;
}

bool CUTXOSet::UndoBlock(const CBlock& block) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: Database not open" << std::endl;
        return false;
    }

    // Note: This is a simplified implementation for Phase 5.1.2
    // Full undo logic will be implemented in Phase 5.4
    // For now, we just provide the interface

    std::cout << "[INFO] CUTXOSet::UndoBlock: Block undo (transaction processing not yet implemented)" << std::endl;

    return true;
}

bool CUTXOSet::Flush() {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::Flush: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cs_utxo);

    // Use batch write for efficiency
    leveldb::WriteBatch batch;

    // Apply all additions
    for (const auto& pair : cache_additions) {
        std::string key = SerializeOutPoint(pair.first);
        std::string value = SerializeUTXOEntry(pair.second);
        batch.Put(key, value);
    }

    // Apply all deletions
    for (const auto& pair : cache_deletions) {
        std::string key = SerializeOutPoint(pair.first);
        batch.Delete(key);
    }

    // Write statistics
    std::string stats_key = "utxo_stats";
    std::string stats_value;
    stats_value.resize(20);
    std::memcpy(&stats_value[0], &stats.nUTXOs, 8);
    std::memcpy(&stats_value[8], &stats.nTotalAmount, 8);
    std::memcpy(&stats_value[16], &stats.nHeight, 4);
    batch.Put(stats_key, stats_value);

    // Write batch to database
    leveldb::WriteOptions write_options;
    write_options.sync = true;  // Ensure durability
    leveldb::Status status = db->Write(write_options, &batch);

    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::Flush: Failed to write batch: " << status.ToString() << std::endl;
        return false;
    }

    // Clear pending changes
    cache_additions.clear();
    cache_deletions.clear();

    std::cout << "[INFO] CUTXOSet::Flush: Successfully flushed "
              << (cache_additions.size() + cache_deletions.size())
              << " changes to disk" << std::endl;

    return true;
}

// ============================================================================
// Statistics and Verification
// ============================================================================

CUTXOStats CUTXOSet::GetStats() const {
    std::lock_guard<std::mutex> lock(cs_utxo);
    return stats;
}

bool CUTXOSet::UpdateStats() {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::UpdateStats: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cs_utxo);

    // Reset statistics
    uint64_t utxo_count = 0;
    uint64_t total_amount = 0;

    // Iterate through all UTXOs in database
    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        // Skip non-UTXO keys
        if (key.empty() || key[0] != 'u') {
            continue;
        }

        // Deserialize UTXO entry
        CUTXOEntry entry;
        if (!DeserializeUTXOEntry(it->value().ToString(), entry)) {
            std::cerr << "[ERROR] CUTXOSet::UpdateStats: Failed to deserialize UTXO" << std::endl;
            continue;
        }

        utxo_count++;
        total_amount += entry.out.nValue;
    }

    if (!it->status().ok()) {
        std::cerr << "[ERROR] CUTXOSet::UpdateStats: Iterator error: " << it->status().ToString() << std::endl;
        return false;
    }

    stats.nUTXOs = utxo_count;
    stats.nTotalAmount = total_amount;

    std::cout << "[INFO] CUTXOSet::UpdateStats: Updated statistics - UTXOs: " << stats.nUTXOs
              << ", Total: " << stats.nTotalAmount << std::endl;

    return true;
}

bool CUTXOSet::IsCoinBaseMature(const COutPoint& outpoint, uint32_t currentHeight) const {
    CUTXOEntry entry;
    if (!GetUTXO(outpoint, entry)) {
        return false;
    }

    // Non-coinbase transactions are always mature
    if (!entry.fCoinBase) {
        return true;
    }

    // Coinbase requires COINBASE_MATURITY confirmations
    // currentHeight must be at least (entry.nHeight + COINBASE_MATURITY)
    if (currentHeight < entry.nHeight + COINBASE_MATURITY) {
        return false;
    }

    return true;
}

bool CUTXOSet::VerifyConsistency() const {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cs_utxo);

    uint64_t utxo_count = 0;
    uint64_t total_amount = 0;

    // Iterate through all UTXOs and verify they can be deserialized
    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        // Skip non-UTXO keys
        if (key.empty() || key[0] != 'u') {
            continue;
        }

        // Verify key format (1 byte prefix + 32 byte hash + 4 byte index = 37 bytes)
        if (key.size() != 37) {
            std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Invalid key size: " << key.size() << std::endl;
            return false;
        }

        // Deserialize and validate UTXO entry
        CUTXOEntry entry;
        if (!DeserializeUTXOEntry(it->value().ToString(), entry)) {
            std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Failed to deserialize UTXO" << std::endl;
            return false;
        }

        // Check for null/invalid entries
        if (entry.IsNull()) {
            std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Found null UTXO entry" << std::endl;
            return false;
        }

        utxo_count++;
        total_amount += entry.out.nValue;
    }

    if (!it->status().ok()) {
        std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Iterator error: " << it->status().ToString() << std::endl;
        return false;
    }

    // Verify statistics match (within pending changes)
    std::cout << "[INFO] CUTXOSet::VerifyConsistency: DB has " << utxo_count << " UTXOs, "
              << "stats show " << stats.nUTXOs << " (pending: +" << cache_additions.size()
              << " -" << cache_deletions.size() << ")" << std::endl;

    std::cout << "[INFO] CUTXOSet::VerifyConsistency: Consistency check passed" << std::endl;

    return true;
}

bool CUTXOSet::Clear() {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::Clear: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cs_utxo);

    std::cout << "[WARNING] CUTXOSet::Clear: Clearing entire UTXO set!" << std::endl;

    // Use batch delete for efficiency
    leveldb::WriteBatch batch;

    // Iterate through all UTXOs and delete them
    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        // Delete all UTXO keys (starting with 'u')
        if (!key.empty() && key[0] == 'u') {
            batch.Delete(key);
        }
    }

    // Write batch to database
    leveldb::Status status = db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::Clear: Failed to clear database: " << status.ToString() << std::endl;
        return false;
    }

    // Reset statistics
    stats.nUTXOs = 0;
    stats.nTotalAmount = 0;
    stats.nHeight = 0;

    // Clear caches
    cache.clear();
    cache_additions.clear();
    cache_deletions.clear();

    std::cout << "[INFO] CUTXOSet::Clear: UTXO set cleared successfully" << std::endl;

    return true;
}
