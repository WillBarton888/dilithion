// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_UTXO_SET_H
#define DILITHION_NODE_UTXO_SET_H

#include <primitives/transaction.h>
#include <primitives/block.h>
#include <leveldb/db.h>
#include <string>
#include <memory>
#include <mutex>
#include <map>

/**
 * UTXO (Unspent Transaction Output) entry
 * Stores information about a single unspent output
 */
struct CUTXOEntry {
    CTxOut out;           // The transaction output itself
    uint32_t nHeight;     // Block height where this UTXO was created
    bool fCoinBase;       // True if this is from a coinbase transaction

    CUTXOEntry() : nHeight(0), fCoinBase(false) {}
    CUTXOEntry(const CTxOut& outIn, uint32_t nHeightIn, bool fCoinBaseIn)
        : out(outIn), nHeight(nHeightIn), fCoinBase(fCoinBaseIn) {}

    bool IsNull() const { return out.IsNull(); }
    void SetNull() { out.SetNull(); nHeight = 0; fCoinBase = false; }
};

/**
 * UTXO Set Statistics
 * Tracks overall UTXO set metrics
 */
struct CUTXOStats {
    uint64_t nUTXOs;           // Total number of UTXOs
    uint64_t nTotalAmount;     // Total amount in all UTXOs
    uint32_t nHeight;          // Current block height

    CUTXOStats() : nUTXOs(0), nTotalAmount(0), nHeight(0) {}
};

/**
 * UTXO Set Database
 *
 * Manages the set of all unspent transaction outputs (UTXOs) using LevelDB.
 * This is critical infrastructure for transaction validation and wallet balance calculation.
 *
 * Features:
 * - Persistent storage via LevelDB
 * - Memory cache for frequently accessed UTXOs
 * - Batch operations for block application/rollback
 * - Thread-safe operations
 * - Coinbase maturity handling
 */
class CUTXOSet
{
private:
    std::unique_ptr<leveldb::DB> db;
    mutable std::mutex cs_utxo;
    std::string datadir;

    // Memory cache for frequently accessed UTXOs
    // Maps COutPoint to UTXO entry
    mutable std::map<COutPoint, CUTXOEntry> cache;

    // Track modifications for batch updates
    std::map<COutPoint, CUTXOEntry> cache_additions;
    std::map<COutPoint, bool> cache_deletions;  // bool is just a placeholder

    // Statistics
    CUTXOStats stats;

    // Coinbase maturity requirement (100 blocks like Bitcoin)
    static const uint32_t COINBASE_MATURITY = 100;

    // Helper functions for serialization
    std::string SerializeOutPoint(const COutPoint& outpoint) const;
    std::string SerializeUTXOEntry(const CUTXOEntry& entry) const;
    bool DeserializeUTXOEntry(const std::string& data, CUTXOEntry& entry) const;

    // Internal cache management
    void UpdateCache(const COutPoint& outpoint, const CUTXOEntry& entry) const;
    void RemoveFromCache(const COutPoint& outpoint) const;
    bool GetFromCache(const COutPoint& outpoint, CUTXOEntry& entry) const;

public:
    CUTXOSet();
    ~CUTXOSet();

    /**
     * Open the UTXO database at the specified path
     * @param path Directory path for the UTXO database
     * @param create_if_missing Create database if it doesn't exist
     * @return true if successful
     */
    bool Open(const std::string& path, bool create_if_missing = true);

    /**
     * Close the UTXO database
     */
    void Close();

    /**
     * Check if the database is open
     * @return true if database is open
     */
    bool IsOpen() const;

    /**
     * Lookup a UTXO by outpoint
     * @param outpoint The transaction output point to lookup
     * @param entry Reference to store the UTXO entry if found
     * @return true if UTXO exists and is unspent
     */
    bool GetUTXO(const COutPoint& outpoint, CUTXOEntry& entry) const;

    /**
     * Check if a UTXO exists without retrieving it
     * @param outpoint The transaction output point to check
     * @return true if UTXO exists and is unspent
     */
    bool HaveUTXO(const COutPoint& outpoint) const;

    /**
     * Add a new UTXO to the set
     * @param outpoint The transaction output point
     * @param out The transaction output data
     * @param height Block height where this UTXO was created
     * @param fCoinBase Whether this is from a coinbase transaction
     * @return true if successful
     */
    bool AddUTXO(const COutPoint& outpoint, const CTxOut& out, uint32_t height, bool fCoinBase);

    /**
     * Spend (remove) a UTXO from the set
     * @param outpoint The transaction output point to spend
     * @return true if successful (UTXO existed and was removed)
     */
    bool SpendUTXO(const COutPoint& outpoint);

    /**
     * Apply all transactions from a block to the UTXO set
     * This adds all outputs and spends all inputs (except coinbase)
     * @param block The block to apply
     * @param height The height of this block
     * @return true if successful
     */
    bool ApplyBlock(const CBlock& block, uint32_t height);

    /**
     * Undo all transactions from a block (for chain reorganization)
     * This reverses the effects of ApplyBlock
     * @param block The block to undo
     * @return true if successful
     */
    bool UndoBlock(const CBlock& block);

    /**
     * Flush all pending changes to disk
     * This writes all cached additions/deletions to LevelDB
     * @return true if successful
     */
    bool Flush();

    /**
     * Get UTXO set statistics
     * @return Current UTXO statistics
     */
    CUTXOStats GetStats() const;

    /**
     * Update statistics by scanning the entire UTXO set
     * This is expensive and should only be called during initialization
     * or periodic consistency checks
     * @return true if successful
     */
    bool UpdateStats();

    /**
     * Check if a coinbase UTXO is mature (can be spent)
     * Coinbase outputs require COINBASE_MATURITY confirmations
     * @param outpoint The UTXO to check
     * @param currentHeight Current blockchain height
     * @return true if UTXO is spendable at currentHeight
     */
    bool IsCoinBaseMature(const COutPoint& outpoint, uint32_t currentHeight) const;

    /**
     * Verify UTXO set consistency
     * Checks internal data structures for corruption
     * @return true if UTXO set is consistent
     */
    bool VerifyConsistency() const;

    /**
     * Clear all UTXOs (use with caution - for testing/reindexing only)
     * @return true if successful
     */
    bool Clear();

    /**
     * Get the total number of UTXOs in the set
     * @return UTXO count
     */
    uint64_t GetUTXOCount() const { return stats.nUTXOs; }

    /**
     * Get the total amount in all UTXOs (monetary supply)
     * @return Total amount in satoshis
     */
    uint64_t GetTotalAmount() const { return stats.nTotalAmount; }
};

#endif // DILITHION_NODE_UTXO_SET_H
