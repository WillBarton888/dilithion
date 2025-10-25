// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/blockchain_storage.h>
#include <leveldb/write_batch.h>
#include <leveldb/options.h>
#include <cstring>
#include <iostream>

CBlockchainDB::CBlockchainDB() : db(nullptr) {}

CBlockchainDB::~CBlockchainDB() {
    Close();
}

bool CBlockchainDB::Open(const std::string& path, bool create_if_missing) {
    std::lock_guard<std::mutex> lock(cs_db);

    if (db != nullptr) {
        return true;  // Already open
    }

    datadir = path;

    leveldb::Options options;
    options.create_if_missing = create_if_missing;
    options.compression = leveldb::kSnappyCompression;

    leveldb::DB* raw_db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &raw_db);

    if (!status.ok()) {
        std::cerr << "Failed to open database: " << status.ToString() << std::endl;
        return false;
    }

    db.reset(raw_db);
    return true;
}

void CBlockchainDB::Close() {
    std::lock_guard<std::mutex> lock(cs_db);
    db.reset();
}

bool CBlockchainDB::IsOpen() const {
    std::lock_guard<std::mutex> lock(cs_db);
    return db != nullptr;
}

bool CBlockchainDB::WriteBlock(const uint256& hash, const CBlock& block) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    // Serialize block (simplified for now)
    std::string key = "b" + hash.GetHex();

    // In production, would properly serialize the block
    // For now, basic placeholder
    std::string value;  // TODO: Implement block serialization

    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

bool CBlockchainDB::ReadBlock(const uint256& hash, CBlock& block) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "b" + hash.GetHex();
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);

    if (!status.ok()) {
        return false;
    }

    // TODO: Implement block deserialization
    return true;
}

bool CBlockchainDB::WriteBlockIndex(const uint256& hash, const CBlockIndex& index) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "i" + hash.GetHex();

    // Serialize index (simplified)
    std::string value;  // TODO: Implement index serialization

    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

bool CBlockchainDB::ReadBlockIndex(const uint256& hash, CBlockIndex& index) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "i" + hash.GetHex();
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return false;
    }

    // TODO: Implement index deserialization
    return true;
}

bool CBlockchainDB::WriteBestBlock(const uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "bestblock";
    std::string value = hash.GetHex();

    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

bool CBlockchainDB::ReadBestBlock(uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "bestblock";
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return false;
    }

    hash.SetHex(value);
    return true;
}

bool CBlockchainDB::BlockExists(const uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "b" + hash.GetHex();
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    return status.ok();
}

bool CBlockchainDB::EraseBlock(const uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "b" + hash.GetHex();

    leveldb::Status status = db->Delete(leveldb::WriteOptions(), key);
    return status.ok();
}
