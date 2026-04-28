// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <index/tx_index.h>

#include <consensus/validation.h>
#include <node/blockchain_storage.h>
#include <primitives/transaction.h>

#include <leveldb/db.h>
#include <leveldb/options.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>
#include <leveldb/write_batch.h>

#include <cstring>
#include <iostream>

std::unique_ptr<CTxIndex> g_tx_index;

const std::string CTxIndex::META_KEY = std::string("\x00meta", 5);

CTxIndex::CTxIndex() = default;

CTxIndex::~CTxIndex() {
    Stop();
    std::lock_guard<std::mutex> lock(m_mutex);
    m_db.reset();
}

std::string CTxIndex::MakeTxKey(const uint256& txid) {
    std::string key;
    key.reserve(TX_KEY_SIZE);
    key.push_back('t');
    key.append(reinterpret_cast<const char*>(txid.data), 32);
    return key;
}

bool CTxIndex::WriteMeta(leveldb::WriteBatch& batch, int height, const uint256& hash) {
    char value[META_VALUE_SIZE];
    value[0] = static_cast<char>(SCHEMA_VERSION);
    int32_t h_le = static_cast<int32_t>(height);
    std::memcpy(&value[1], &h_le, 4);
    std::memcpy(&value[5], hash.data, 8);
    batch.Put(leveldb::Slice(META_KEY.data(), META_KEY.size()),
              leveldb::Slice(value, META_VALUE_SIZE));
    return true;
}

bool CTxIndex::Init(const std::string& datadir, CBlockchainDB* chain_db) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_db) {
        // Already initialized
        return true;
    }

    m_chain_db = chain_db;

    leveldb::Options options;
    options.create_if_missing = true;
    options.write_buffer_size = 4 * 1024 * 1024;
    options.max_open_files = 100;

    leveldb::DB* db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, datadir, &db);
    if (!status.ok()) {
        std::cerr << "[txindex] Failed to open index database at " << datadir
                  << ": " << status.ToString() << std::endl;
        return false;
    }
    m_db.reset(db);

    std::string meta_value;
    leveldb::Status meta_status = m_db->Get(
        leveldb::ReadOptions(),
        leveldb::Slice(META_KEY.data(), META_KEY.size()),
        &meta_value);

    if (meta_status.IsNotFound()) {
        m_last_height.store(-1);
        m_synced.store(false);
        return true;
    }

    if (!meta_status.ok()) {
        std::cerr << "[txindex] Failed to read meta record: " << meta_status.ToString() << std::endl;
        m_db.reset();
        return false;
    }

    if (meta_value.size() != META_VALUE_SIZE) {
        std::cerr << "[txindex] Meta record has wrong size: " << meta_value.size()
                  << " (expected " << META_VALUE_SIZE << ")" << std::endl;
        m_db.reset();
        return false;
    }

    if (static_cast<uint8_t>(meta_value[0]) != SCHEMA_VERSION) {
        std::cerr << "[txindex] Meta record has unknown schema version: "
                  << static_cast<int>(static_cast<uint8_t>(meta_value[0])) << std::endl;
        m_db.reset();
        return false;
    }

    int32_t height = 0;
    std::memcpy(&height, &meta_value[1], 4);
    m_last_height.store(height);
    m_synced.store(false);

    return true;
}

bool CTxIndex::WriteBlock(const CBlock& block, int height, const uint256& block_hash) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    if (height <= m_last_height.load()) {
        // Already indexed (or earlier height); monotonicity no-op (C1).
        return true;
    }

    std::vector<CTransactionRef> txs;
    std::string err;
    CBlockValidator validator;
    if (!validator.DeserializeBlockTransactions(block, txs, err)) {
        std::cerr << "[txindex] Failed to deserialize block transactions at height "
                  << height << ": " << err << std::endl;
        return false;
    }

    leveldb::WriteBatch batch;

    char value[TX_VALUE_SIZE];
    std::memset(value, 0, TX_VALUE_SIZE);
    value[0] = static_cast<char>(SCHEMA_VERSION);
    std::memcpy(&value[1], block_hash.data, 32);

    for (size_t i = 0; i < txs.size(); ++i) {
        uint32_t pos_le = static_cast<uint32_t>(i);
        std::memcpy(&value[33], &pos_le, 4);
        std::string key = MakeTxKey(txs[i]->GetHash());
        batch.Put(leveldb::Slice(key.data(), key.size()),
                  leveldb::Slice(value, TX_VALUE_SIZE));
    }

    if (!WriteMeta(batch, height, block_hash)) {
        return false;
    }

    leveldb::Status status = m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[txindex] WriteBlock failed at height " << height
                  << ": " << status.ToString() << std::endl;
        return false;
    }

    m_last_height.store(height);
    return true;
}

bool CTxIndex::EraseBlock(const CBlock& block, int height, const uint256& block_hash) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    std::vector<CTransactionRef> txs;
    std::string err;
    CBlockValidator validator;
    if (!validator.DeserializeBlockTransactions(block, txs, err)) {
        std::cerr << "[txindex] Failed to deserialize block transactions during EraseBlock at height "
                  << height << ": " << err << std::endl;
        return false;
    }

    leveldb::WriteBatch batch;
    for (const auto& tx : txs) {
        std::string key = MakeTxKey(tx->GetHash());
        batch.Delete(leveldb::Slice(key.data(), key.size()));
    }

    int new_height = (height > 0) ? (height - 1) : -1;
    uint256 prev_hash;
    if (height > 0) {
        prev_hash = block.hashPrevBlock;
    }
    if (!WriteMeta(batch, new_height, prev_hash)) {
        return false;
    }

    leveldb::Status status = m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[txindex] EraseBlock failed at height " << height
                  << ": " << status.ToString() << std::endl;
        return false;
    }

    m_last_height.store(new_height);
    (void)block_hash;
    return true;
}

bool CTxIndex::FindTx(const uint256& txid, uint256& block_hash, uint32_t& tx_pos) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    std::string key = MakeTxKey(txid);
    std::string value;
    leveldb::Status status = m_db->Get(leveldb::ReadOptions(),
                                       leveldb::Slice(key.data(), key.size()),
                                       &value);
    if (!status.ok()) {
        return false;
    }

    if (value.size() != TX_VALUE_SIZE) {
        return false;
    }

    if (static_cast<uint8_t>(value[0]) != SCHEMA_VERSION) {
        return false;
    }

    std::memcpy(block_hash.data, &value[1], 32);
    uint32_t pos_le = 0;
    std::memcpy(&pos_le, &value[33], 4);
    tx_pos = pos_le;

    return true;
}

int CTxIndex::LastIndexedHeight() const {
    return m_last_height.load();
}

bool CTxIndex::IsBuiltUpToHeight(int h) const {
    return m_last_height.load() >= h;
}

bool CTxIndex::IsSynced() const {
    return m_synced.load();
}

void CTxIndex::StartBackgroundSync() {
    // PR-4 implements the reindex thread.
}

void CTxIndex::Interrupt() {
    m_interrupt.store(true);
}

void CTxIndex::Stop() {
    m_interrupt.store(true);
    if (m_sync_thread.joinable()) {
        m_sync_thread.join();
    }
}

void CTxIndex::IncrementMismatches() {
    m_mismatches_observed.fetch_add(1, std::memory_order_relaxed);
}

uint64_t CTxIndex::MismatchCount() const {
    return m_mismatches_observed.load(std::memory_order_relaxed);
}
