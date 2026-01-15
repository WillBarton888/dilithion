// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_CHAIN_H
#define DILITHION_CONSENSUS_CHAIN_H

#include <node/block_index.h>
#include <primitives/block.h>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <atomic>

// Forward declarations
class CBlockchainDB;
class CUTXOSet;
class CReorgWAL;
class CTxMemPool;  // BUG #109 FIX: Mempool for confirmed TX cleanup

/**
 * Chain State Manager
 * Handles chain reorganization and maintains active chain tip
 */
class CChainState
{
private:
    // HIGH-C001 FIX: Use smart pointers for RAII memory management
    // In-memory block index: hash -> unique_ptr<CBlockIndex>
    // This provides O(1) lookup for any block by hash
    // Smart pointers ensure automatic cleanup, preventing memory leaks
    std::map<uint256, std::unique_ptr<CBlockIndex>> mapBlockIndex;

    // Active chain tip (block with most cumulative work)
    CBlockIndex* pindexTip;

    // Database reference for persisting chain state
    CBlockchainDB* pdb;

    // UTXO set reference for chain validation (CS-005)
    CUTXOSet* pUTXOSet;

    // BUG #109 FIX: Mempool reference for removing confirmed transactions
    // When a block is connected, we must remove its transactions from mempool
    // to prevent UTXO/mempool inconsistency (inputs appearing unavailable)
    CTxMemPool* pMemPool{nullptr};

    // P1-4 FIX: Write-Ahead Log for atomic reorganizations
    std::unique_ptr<CReorgWAL> m_reorgWAL;
    bool m_requiresReindex{false};

    // CRITICAL-1 FIX: Mutex for thread-safe access to chain state
    // Protects mapBlockIndex, pindexTip, and all chain operations
    // BUG #200 FIX: Changed to recursive_mutex to allow ActivateBestChain to call
    // DisconnectTip without self-deadlock (both acquire cs_main)
    mutable std::recursive_mutex cs_main;

    // BUG #74 FIX: Atomic cached height for lock-free reads
    // GetHeight() is called frequently by RPC and wallet operations
    // Using cs_main for height reads causes contention with block processing
    // This atomic is updated atomically whenever pindexTip changes
    std::atomic<int> m_cachedHeight{-1};

    // Bug #40 fix: Callback mechanism for tip updates
    // Allows HeadersManager and other components to be notified when chain tip changes
    using TipUpdateCallback = std::function<void(const CBlockIndex*)>;
    std::vector<TipUpdateCallback> m_tipCallbacks;

    // BUG #56 FIX: Block connect/disconnect callbacks (Bitcoin Core pattern)
    // Allows wallet to be notified when blocks are connected/disconnected
    // IBD OPTIMIZATION: Pass hash to avoid RandomX recomputation in callbacks
    using BlockConnectCallback = std::function<void(const CBlock&, int height, const uint256& hash)>;
    using BlockDisconnectCallback = std::function<void(const CBlock&, int height, const uint256& hash)>;
    std::vector<BlockConnectCallback> m_blockConnectCallbacks;
    std::vector<BlockDisconnectCallback> m_blockDisconnectCallbacks;

public:
    CChainState();
    ~CChainState();

    /**
     * Initialize chain state with database
     */
    void SetDatabase(CBlockchainDB* database) { pdb = database; }

    /**
     * Initialize chain state with UTXO set (CS-005)
     */
    void SetUTXOSet(CUTXOSet* utxoSet) { pUTXOSet = utxoSet; }

    /**
     * BUG #109 FIX: Initialize chain state with mempool
     * Required for removing confirmed transactions when blocks are connected
     */
    void SetMemPool(CTxMemPool* mempool) { pMemPool = mempool; }

    /**
     * P1-4 FIX: Initialize Write-Ahead Log for atomic reorganizations
     * MUST be called after SetDatabase() with the data directory
     * @param dataDir The data directory (e.g., ~/.dilithion-testnet)
     * @return true if initialized successfully, false if incomplete reorg detected
     */
    bool InitializeWAL(const std::string& dataDir);

    /**
     * P1-4 FIX: Check if an incomplete reorg was detected on startup
     * @return true if -reindex is required
     */
    bool RequiresReindex() const;

    /**
     * Get current chain tip (most work)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    CBlockIndex* GetTip() const;

    /**
     * Set chain tip (used during initialization)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    void SetTip(CBlockIndex* pindex);

    /**
     * Add block index to in-memory map
     * HIGH-C001 FIX: Now takes unique_ptr for automatic ownership transfer
     */
    bool AddBlockIndex(const uint256& hash, std::unique_ptr<CBlockIndex> pindex);

    /**
     * Get block index by hash
     * Returns nullptr if not found
     */
    CBlockIndex* GetBlockIndex(const uint256& hash);

    /**
     * Check if block index exists in memory
     */
    bool HasBlockIndex(const uint256& hash) const;

    /**
     * Find the last common ancestor between two chains
     * Used to determine fork point during reorganization
     *
     * @param pindex1 Tip of first chain
     * @param pindex2 Tip of second chain
     * @return Pointer to common ancestor, or nullptr if no common ancestor
     */
    static CBlockIndex* FindFork(CBlockIndex* pindex1, CBlockIndex* pindex2);

    /**
     * Attempt to activate the best chain
     * Compares new block's chain work with current tip
     * If new chain has more work, reorganizes to it
     *
     * @param pindexNew Block index of newly received/mined block
     * @param block Full block data (needed for connecting)
     * @param reorgOccurred Output parameter: set to true if reorg happened
     * @return true if block successfully activated (may or may not cause reorg)
     */
    bool ActivateBestChain(CBlockIndex* pindexNew, const CBlock& block, bool& reorgOccurred);

    /**
     * Connect a block to the active chain
     * Updates pnext pointers and marks block as on main chain
     *
     * @param pindex Block index to connect
     * @param block Full block data
     * @return true on success, false on failure
     */
    bool ConnectTip(CBlockIndex* pindex, const CBlock& block);

    /**
     * Disconnect a block from the active chain
     * Clears pnext pointer and marks block as not on main chain
     *
     * @param pindex Block index to disconnect
     * @return true on success, false on failure
     */
    bool DisconnectTip(CBlockIndex* pindex, bool force_skip_utxo = false);

    /**
     * Get blockchain height (height of current tip)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    int GetHeight() const;

    /**
     * Get total chain work (cumulative PoW)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    uint256 GetChainWork() const;

    /**
     * Get all block hashes at a specific height
     * Used for debugging forks and orphan blocks
     */
    std::vector<uint256> GetBlocksAtHeight(int height) const;

    /**
     * Clean up in-memory index
     * Deletes all CBlockIndex pointers
     */
    void Cleanup();

    /**
     * Register callback for chain tip updates (Bug #40)
     * Called whenever ActivateBestChain successfully updates the tip
     *
     * @param callback Function to call with new tip index
     */
    void RegisterTipUpdateCallback(TipUpdateCallback callback);

    /**
     * BUG #56 FIX: Register callback for block connect events
     * Called when a block is connected to the main chain
     *
     * @param callback Function to call with block data and height
     */
    void RegisterBlockConnectCallback(BlockConnectCallback callback);

    /**
     * BUG #56 FIX: Register callback for block disconnect events
     * Called when a block is disconnected from the main chain (reorg)
     *
     * @param callback Function to call with block data and height
     */
    void RegisterBlockDisconnectCallback(BlockDisconnectCallback callback);

    /**
     * RACE CONDITION FIX: Get a thread-safe snapshot of the chain path
     *
     * Returns a vector of (height, hash) pairs for blocks from current tip
     * down to minHeight, walking pprev pointers while holding cs_main.
     *
     * This allows callers to safely compare chainstate with other data
     * without risking use-after-free from concurrent modifications.
     *
     * @param maxBlocks Maximum number of blocks to include in snapshot
     * @param minHeight Stop when reaching this height (0 = genesis)
     * @return Vector of (height, hash) pairs from tip downward
     */
    std::vector<std::pair<int, uint256>> GetChainSnapshot(int maxBlocks = 1000, int minHeight = 0) const;

private:
    /**
     * Notify registered callbacks of tip update (Bug #40)
     * Called after tip successfully updated in ActivateBestChain
     *
     * @param pindex New chain tip
     */
    void NotifyTipUpdate(const CBlockIndex* pindex);
};

#endif // DILITHION_CONSENSUS_CHAIN_H
