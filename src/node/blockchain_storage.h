// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_BLOCKCHAIN_STORAGE_H
#define DILITHION_NODE_BLOCKCHAIN_STORAGE_H

#include <primitives/block.h>
#include <node/block_index.h>
#include <leveldb/db.h>
#include <string>
#include <memory>
#include <mutex>

class CBlockchainDB
{
private:
    std::unique_ptr<leveldb::DB> db;
    mutable std::mutex cs_db;
    std::string datadir;

public:
    CBlockchainDB();
    ~CBlockchainDB();

    bool Open(const std::string& path, bool create_if_missing = true);
    void Close();
    bool IsOpen() const;
    bool WriteBlock(const uint256& hash, const CBlock& block);
    bool ReadBlock(const uint256& hash, CBlock& block);
    bool WriteBlockIndex(const uint256& hash, const CBlockIndex& index);
    bool ReadBlockIndex(const uint256& hash, CBlockIndex& index);
    bool WriteBestBlock(const uint256& hash);
    bool ReadBestBlock(uint256& hash);
    bool BlockExists(const uint256& hash);
    bool EraseBlock(const uint256& hash);
};

#endif
