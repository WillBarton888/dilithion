// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_FORK_CANDIDATE_H
#define DILITHION_NODE_FORK_CANDIDATE_H

#include <primitives/block.h>
#include <uint256.h>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <string>

/**
 * @brief Status of a block within a fork candidate
 *
 * Tracks the validation state of each block in the staged fork.
 */
enum class ForkBlockStatus {
    PENDING,      // Downloaded, awaiting validation
    POW_VALID,    // PoW check passed
    PREVALIDATED, // PoW + MIK/DFMP passed (ready for chain switch)
    INVALID       // Failed validation
};

/**
 * @brief Convert ForkBlockStatus to string for logging
 */
inline const char* ForkBlockStatusToString(ForkBlockStatus status) {
    switch (status) {
        case ForkBlockStatus::PENDING:      return "PENDING";
        case ForkBlockStatus::POW_VALID:    return "POW_VALID";
        case ForkBlockStatus::PREVALIDATED: return "PREVALIDATED";
        case ForkBlockStatus::INVALID:      return "INVALID";
        default:                            return "UNKNOWN";
    }
}

/**
 * @brief A single block within a fork candidate
 *
 * Contains the block data, its validation status, and any error information.
 */
struct ForkBlock {
    CBlock block;               // The actual block data
    uint256 hash;               // Block hash (precomputed for efficiency)
    int32_t height;             // Block height
    ForkBlockStatus status;     // Current validation status
    std::string invalidReason;  // Reason for rejection (if INVALID)

    ForkBlock() : height(0), status(ForkBlockStatus::PENDING) {}

    ForkBlock(const CBlock& blk, const uint256& h, int32_t ht)
        : block(blk), hash(h), height(ht), status(ForkBlockStatus::PENDING) {}

    bool IsPrevalidated() const { return status == ForkBlockStatus::PREVALIDATED; }
    bool IsInvalid() const { return status == ForkBlockStatus::INVALID; }
};

/**
 * @brief Tracks a potential fork being validated
 *
 * A ForkCandidate represents a competing chain that has been detected via
 * header differences. Blocks are staged here and pre-validated (PoW + MIK)
 * before any chain switch is attempted.
 *
 * Key principle: The current chain is NEVER disconnected until ALL fork
 * blocks are pre-validated and ready for activation via ActivateBestChain.
 *
 * Thread-safety: Methods that modify state are protected by m_mutex.
 */
class ForkCandidate {
public:
    /**
     * @brief Construct a new fork candidate
     *
     * @param forkTipHash     Storage hash of the fork's tip block (from competing tips)
     * @param forkPointHeight Height where fork diverges from main chain
     * @param expectedTipHeight Expected height of fork tip
     * @param expectedHashes  Map of height -> storage hash for fork ancestry
     */
    ForkCandidate(const uint256& forkTipHash, int32_t forkPointHeight, int32_t expectedTipHeight,
                  const std::map<int32_t, uint256>& expectedHashes = {});

    // Accessors
    const uint256& GetForkId() const { return m_forkId; }
    int32_t GetForkPointHeight() const { return m_forkPointHeight; }
    int32_t GetExpectedTipHeight() const { return m_expectedTipHeight; }
    int32_t GetBlockCount() const { return m_expectedTipHeight - m_forkPointHeight; }

    /**
     * @brief Add a block to the fork candidate
     *
     * @param block  The block to add
     * @param hash   Precomputed block hash
     * @param height Block height
     * @return true if added successfully, false if duplicate or out of range
     */
    bool AddBlock(const CBlock& block, const uint256& hash, int32_t height);

    /**
     * @brief Get a block at a specific height
     *
     * @param height Block height to retrieve
     * @return Pointer to ForkBlock, or nullptr if not present
     */
    ForkBlock* GetBlockAtHeight(int32_t height);
    const ForkBlock* GetBlockAtHeight(int32_t height) const;

    /**
     * @brief Check if all expected blocks have been received
     */
    bool HasAllBlocks() const;

    /**
     * @brief Check if all received blocks are pre-validated
     */
    bool AllBlocksPrevalidated() const;

    /**
     * @brief Check if any block has failed validation
     */
    bool HasValidationFailure() const { return m_validationFailed.load(); }

    /**
     * @brief Mark that a validation failure occurred
     */
    void SetValidationFailed() { m_validationFailed.store(true); }

    /**
     * @brief Check if fork has timed out (60s of no blocks)
     */
    bool IsTimedOut() const;

    /**
     * @brief Update the last block received timestamp
     */
    void TouchLastBlockTime();

    /**
     * @brief Get all blocks in height order for chain switch
     *
     * @return Vector of (height, ForkBlock*) pairs, sorted by height ascending
     */
    std::vector<std::pair<int32_t, ForkBlock*>> GetBlocksInOrder();

    /**
     * @brief Get fork statistics for logging
     */
    std::string GetStats() const;

    /**
     * @brief Check if a block hash belongs to this fork
     *
     * Uses the expected hashes map (storage hashes from ancestry walk).
     * This is the reliable way to verify fork membership - not just height range.
     *
     * @param hash   Storage hash of the block
     * @param height Block height
     * @return true if this hash is expected at this height in the fork
     */
    bool IsExpectedBlock(const uint256& hash, int32_t height) const;

    /**
     * @brief Check if expected hashes are available for fork membership checks
     */
    bool HasExpectedHashes() const;

    /**
     * @brief Get expected hash at a height (if available)
     * @return The expected storage hash, or null hash if not available
     */
    uint256 GetExpectedHashAtHeight(int32_t height) const;

private:
    uint256 m_forkId;                  // Storage hash of fork tip (unique identifier)
    int32_t m_forkPointHeight;         // Height where fork diverges
    int32_t m_expectedTipHeight;       // Expected tip height

    mutable std::mutex m_mutex;        // Protects m_blocks
    std::map<int32_t, ForkBlock> m_blocks;  // height -> ForkBlock

    std::map<int32_t, uint256> m_expectedHashes;  // height -> expected storage hash

    std::atomic<bool> m_validationFailed{false};  // Any block failed?

    std::chrono::steady_clock::time_point m_lastBlockTime;  // For timeout detection

    static constexpr int FORK_TIMEOUT_SECONDS = 60;  // Timeout for fork completion
};

#endif // DILITHION_NODE_FORK_CANDIDATE_H
