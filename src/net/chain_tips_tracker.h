// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_CHAIN_TIPS_TRACKER_H
#define DILITHION_NET_CHAIN_TIPS_TRACKER_H

#include <primitives/block.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <mutex>
#include <map>
#include <set>
#include <vector>
#include <chrono>

/**
 * @file chain_tips_tracker.h
 * @brief Tracks competing chain tips for fork-aware header synchronization
 *
 * Bug #150 Fix: This component enables proper fork handling by tracking
 * all known chain tips with their cumulative work, allowing selection of
 * the best-work chain during header sync.
 *
 * Ported from Bitcoin Core's chain tip management concepts.
 */

// Forward declarations
typedef int NodeId;

/**
 * @struct ChainTip
 * @brief Represents a chain tip (leaf in the header tree)
 *
 * A chain tip is a header that has no children. Multiple tips indicate
 * competing forks. The tip with highest cumulative work is the "best" chain.
 */
struct ChainTip {
    uint256 hash;                ///< Block hash of this tip
    int height;                  ///< Height in chain
    arith_uint256 chainWork;     ///< Cumulative proof-of-work from genesis
    NodeId peer;                 ///< Which peer served this chain (for debugging)
    std::chrono::steady_clock::time_point lastSeen;  ///< When we last received from this chain

    ChainTip() : height(0), peer(-1) {
        lastSeen = std::chrono::steady_clock::now();
    }

    ChainTip(const uint256& h, int ht, const arith_uint256& work, NodeId p = -1)
        : hash(h), height(ht), chainWork(work), peer(p) {
        lastSeen = std::chrono::steady_clock::now();
    }

    // Comparison by chain work (descending - more work is better)
    bool operator<(const ChainTip& other) const {
        // Primary: more chain work wins
        if (chainWork != other.chainWork) {
            return chainWork > other.chainWork;  // Reversed for descending order
        }
        // Tiebreaker: use hash (arbitrary but deterministic)
        return hash < other.hash;
    }
};

/**
 * @class CChainTipsTracker
 * @brief Manages competing chain tips for fork selection
 *
 * Thread-safe tracker for all known chain tips. Used to:
 * - Detect when a fork becomes the best chain
 * - Identify chains that should be pruned (low work, stale)
 * - Provide fork statistics for debugging
 */
class CChainTipsTracker {
public:
    CChainTipsTracker() = default;
    ~CChainTipsTracker() = default;

    // Disable copying
    CChainTipsTracker(const CChainTipsTracker&) = delete;
    CChainTipsTracker& operator=(const CChainTipsTracker&) = delete;

    /**
     * @brief Add or update a chain tip
     *
     * If this hash already exists as a tip, updates its metadata.
     * Otherwise, adds as a new competing chain tip.
     *
     * @param hash Block hash
     * @param height Block height
     * @param chainWork Cumulative chain work
     * @param peer Peer that served this chain
     * @return true if this is now the best tip
     */
    bool AddOrUpdateTip(const uint256& hash, int height,
                        const arith_uint256& chainWork, NodeId peer = -1);

    /**
     * @brief Remove a chain tip (when child extends it)
     *
     * Called when a header's parent is no longer a tip (has a child now).
     *
     * @param hash Block hash to remove from tips
     */
    void RemoveTip(const uint256& hash);

    /**
     * @brief Get the best (highest work) chain tip
     *
     * @return Hash of best tip, or null if no tips
     */
    uint256 GetBestTip() const;

    /**
     * @brief Get the best tip's chain work
     *
     * @return Chain work of best tip
     */
    arith_uint256 GetBestChainWork() const;

    /**
     * @brief Get all competing tips sorted by chain work
     *
     * @return Vector of tips (best first)
     */
    std::vector<ChainTip> GetCompetingTips() const;

    /**
     * @brief Check if a hash is currently a chain tip
     *
     * @param hash Block hash to check
     * @return true if this hash is a known tip
     */
    bool IsTip(const uint256& hash) const;

    /**
     * @brief Get number of competing chain tips
     *
     * More than 1 tip indicates active forks.
     *
     * @return Number of tips
     */
    size_t TipCount() const;

    /**
     * @brief Check if we have competing forks
     *
     * @return true if more than one chain tip exists
     */
    bool HasCompetingForks() const;

    /**
     * @brief Get tips that are significantly behind best tip
     *
     * Returns tips with less than (best_work * threshold_percent / 100) work.
     * These are candidates for pruning.
     *
     * @param threshold_percent Percentage of best work (e.g., 50 = 50%)
     * @return Vector of weak tip hashes
     */
    std::vector<uint256> GetWeakTips(int threshold_percent = 50) const;

    /**
     * @brief Get tips that haven't been updated recently
     *
     * Returns tips not seen for more than max_age_seconds.
     * These are candidates for pruning.
     *
     * @param max_age_seconds Maximum age in seconds
     * @return Vector of stale tip hashes
     */
    std::vector<uint256> GetStaleTips(int max_age_seconds = 3600) const;

    /**
     * @brief Prune tips below minimum chain work
     *
     * Removes tips that have less than the specified minimum work.
     * Used for DoS protection.
     *
     * @param minWork Minimum required chain work
     * @return Number of tips removed
     */
    size_t PruneBelowWork(const arith_uint256& minWork);

    /**
     * @brief Clear all tips
     */
    void Clear();

    /**
     * @brief Get debug info about all tips
     *
     * @return Human-readable string describing all tips
     */
    std::string GetDebugInfo() const;

private:
    mutable std::mutex cs_tips;

    //! All known chain tips indexed by hash
    std::map<uint256, ChainTip> m_tips;

    //! Best tip hash (cached)
    uint256 m_bestTip;

    //! Best chain work (cached)
    arith_uint256 m_bestWork;

    /**
     * @brief Recalculate best tip after modification
     */
    void RecalculateBest();
};

#endif // DILITHION_NET_CHAIN_TIPS_TRACKER_H
