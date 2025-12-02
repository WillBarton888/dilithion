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

    // DB-004 FIX: Path validation helper
    bool ValidateDatabasePath(const std::string& path, std::string& canonical_path);

public:
    CBlockchainDB();
    ~CBlockchainDB();

    bool Open(const std::string& path, bool create_if_missing = true);
    void Close();
    bool IsOpen() const;

    // Original single-operation methods
    bool WriteBlock(const uint256& hash, const CBlock& block);
    bool ReadBlock(const uint256& hash, CBlock& block);
    bool WriteBlockIndex(const uint256& hash, const CBlockIndex& index);
    bool ReadBlockIndex(const uint256& hash, CBlockIndex& index);
    bool WriteBestBlock(const uint256& hash);
    bool ReadBestBlock(uint256& hash);
    bool BlockExists(const uint256& hash);
    bool EraseBlock(const uint256& hash);

    // DB-002 FIX: Atomic batch write for block + index
    bool WriteBlockWithIndex(const uint256& hash, const CBlock& block,
                             const CBlockIndex& index, bool setBest = false);

    // DB-010 FIX: Disk space checking
    bool CheckDiskSpace(uint64_t min_bytes = 1ULL * 1024 * 1024 * 1024) const;

    // Phase 4.2: Fsync verification
    /**
     * Verify that a write operation was successfully persisted to disk
     * 
     * This performs a read-back verification to ensure data was actually
     * written to disk, not just buffered in memory.
     * 
     * @param key Key that was written
     * @param expected_value Expected value that should be on disk
     * @return true if verification succeeds, false otherwise
     */
    bool VerifyWrite(const std::string& key, const std::string& expected_value) const;

    // Phase 4.2: Reindex support
    /**
     * Rebuild block index from blocks on disk
     * 
     * This scans all blocks in the database and rebuilds the block index.
     * Used by -reindex flag to recover from corruption.
     * 
     * @return true on success, false on failure
     */
    bool RebuildBlockIndex();
    
    /**
     * Get all block hashes in the database
     * 
     * @param block_hashes Output vector to store block hashes
     * @return true on success, false on failure
     */
    bool GetAllBlockHashes(std::vector<uint256>& block_hashes) const;
};

#endif
