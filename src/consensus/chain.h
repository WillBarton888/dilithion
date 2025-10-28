// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_CHAIN_H
#define DILITHION_CONSENSUS_CHAIN_H

#include <node/block_index.h>
#include <primitives/block.h>
#include <map>
#include <vector>

// Forward declarations
class CBlockchainDB;
class CUTXOSet;

/**
 * Chain State Manager
 * Handles chain reorganization and maintains active chain tip
 */
class CChainState
{
private:
    // In-memory block index: hash -> CBlockIndex*
    // This provides O(1) lookup for any block by hash
    std::map<uint256, CBlockIndex*> mapBlockIndex;

    // Active chain tip (block with most cumulative work)
    CBlockIndex* pindexTip;

    // Database reference for persisting chain state
    CBlockchainDB* pdb;

    // UTXO set reference for chain validation (CS-005)
    CUTXOSet* pUTXOSet;

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
     * Get current chain tip (most work)
     */
    CBlockIndex* GetTip() const { return pindexTip; }

    /**
     * Set chain tip (used during initialization)
     */
    void SetTip(CBlockIndex* pindex) { pindexTip = pindex; }

    /**
     * Add block index to in-memory map
     * Takes ownership of pindex pointer
     */
    bool AddBlockIndex(const uint256& hash, CBlockIndex* pindex);

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
    bool DisconnectTip(CBlockIndex* pindex);

    /**
     * Get blockchain height (height of current tip)
     */
    int GetHeight() const {
        return pindexTip ? pindexTip->nHeight : -1;
    }

    /**
     * Get total chain work (cumulative PoW)
     */
    uint256 GetChainWork() const {
        return pindexTip ? pindexTip->nChainWork : uint256();
    }

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
};

#endif // DILITHION_CONSENSUS_CHAIN_H
