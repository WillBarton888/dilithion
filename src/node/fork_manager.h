// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_FORK_MANAGER_H
#define DILITHION_NODE_FORK_MANAGER_H

#include <node/fork_candidate.h>
#include <uint256.h>
#include <memory>
#include <mutex>
#include <string>

// Forward declarations
class CBlock;
class CBlockchainDB;
class CChainState;
struct NodeContext;

namespace Dilithion {
    class ChainParams;
}

/**
 * @brief Singleton manager for fork validation and chain switching
 *
 * The ForkManager implements "validate before disconnect" - fork blocks
 * are staged and pre-validated (PoW + MIK) before any chain changes occur.
 *
 * ## Workflow:
 * 1. Fork detected via header differences (in IBDCoordinator)
 * 2. CreateForkCandidate() called to start staging
 * 3. Blocks arrive and are routed to AddBlockToFork()
 * 4. Each block is pre-validated (PoW + MIK via PreValidateBlock)
 * 5. When all blocks received and pre-validated:
 *    - TriggerChainSwitch() calls ActivateBestChain
 *    - ActivateBestChain handles WAL, UTXO, disconnect/connect
 * 6. If any block fails pre-validation:
 *    - CancelFork() is called
 *    - Original chain remains untouched
 *
 * ## Thread Safety:
 * All methods are thread-safe via internal mutex.
 *
 * ## Key Principle:
 * The current chain is NEVER disconnected until ALL fork blocks
 * are pre-validated and ready for activation.
 */
class ForkManager {
public:
    /**
     * @brief Get the singleton instance
     */
    static ForkManager& GetInstance();

    // Non-copyable, non-movable
    ForkManager(const ForkManager&) = delete;
    ForkManager& operator=(const ForkManager&) = delete;
    ForkManager(ForkManager&&) = delete;
    ForkManager& operator=(ForkManager&&) = delete;

    /**
     * @brief Create a new fork candidate for staging
     *
     * Called when a fork is detected (header hash mismatch).
     * Only one fork can be active at a time.
     *
     * @param forkTipHash      Storage hash of the fork's tip block (from competing tips)
     * @param forkPointHeight  Height where fork diverges from main chain
     * @param expectedTipHeight Expected height of fork tip
     * @param expectedHashes   Map of height -> storage hash for fork ancestry
     * @return Shared pointer to the fork candidate, or nullptr if already active
     */
    std::shared_ptr<ForkCandidate> CreateForkCandidate(
        const uint256& forkTipHash,
        int32_t forkPointHeight,
        int32_t expectedTipHeight,
        const std::map<int32_t, uint256>& expectedHashes = {}
    );

    /**
     * @brief Cancel the active fork
     *
     * Called when:
     * - Pre-validation fails
     * - Fork times out
     * - Header is invalidated
     *
     * @param reason Reason for cancellation (for logging)
     */
    void CancelFork(const std::string& reason);

    /**
     * @brief Get the active fork candidate
     *
     * @return Shared pointer to active fork, or nullptr if none
     */
    std::shared_ptr<ForkCandidate> GetActiveFork();

    /**
     * @brief Check if there's an active fork being validated
     */
    bool HasActiveFork() const;

    /**
     * @brief Check if a block hash belongs to the active fork
     *
     * @param blockHash Hash to check
     * @param height Height to check
     * @return true if this block is expected by the active fork
     */
    bool IsBlockForActiveFork(const uint256& blockHash, int32_t height) const;

    /**
     * @brief Add a block to the active fork
     *
     * Stores the block and triggers pre-validation.
     *
     * @param block  The block to add
     * @param hash   Precomputed block hash
     * @param height Block height
     * @return true if added and pre-validated successfully
     */
    bool AddBlockToFork(const CBlock& block, const uint256& hash, int32_t height);

    /**
     * @brief Pre-validate a fork block (PoW + MIK, no chain changes)
     *
     * Validates:
     * - Proof of Work (CheckProofOfWork)
     * - MIK/DFMP signature (CheckProofOfWorkDFMP)
     * - Basic block structure
     *
     * @param forkBlock Block to validate (status updated)
     * @param db        Database for MIK lookups
     * @return true if all checks pass
     */
    bool PreValidateBlock(ForkBlock& forkBlock, CBlockchainDB& db);

    /**
     * @brief Trigger chain switch via ActivateBestChain
     *
     * Called when all fork blocks are received and pre-validated.
     * Uses ActivateBestChain for safe switch with:
     * - WAL crash safety
     * - UTXO disconnect/connect
     * - Reorg depth limits
     * - Checkpoint validation
     *
     * @param ctx     Node context with chainstate
     * @param db      Blockchain database
     * @return true if switch succeeded
     */
    bool TriggerChainSwitch(NodeContext& ctx, CBlockchainDB& db);

    /**
     * @brief Clear in-flight block state after fork cancel/complete
     *
     * Must be called to prevent stale downloads.
     *
     * @param ctx             Node context with block_fetcher
     * @param forkPointHeight Height to clear above
     */
    void ClearInFlightState(NodeContext& ctx, int32_t forkPointHeight);

    /**
     * @brief Check if the active fork has timed out
     *
     * @return true if fork exists and has timed out (60s)
     */
    bool CheckTimeout();

    /**
     * @brief Get statistics string for logging
     */
    std::string GetStats() const;

private:
    ForkManager() = default;

    mutable std::mutex m_mutex;
    std::shared_ptr<ForkCandidate> m_activeFork;

    // Validation helpers
    bool ValidatePoW(const CBlock& block, const uint256& hash);
    bool ValidateMIK(const CBlock& block, int32_t height, CBlockchainDB& db);
    bool ValidateBlockStructure(const CBlock& block);
};

#endif // DILITHION_NODE_FORK_MANAGER_H
