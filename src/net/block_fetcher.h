// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_BLOCK_FETCHER_H
#define DILITHION_NET_BLOCK_FETCHER_H

#include <primitives/block.h>
#include <chrono>
#include <mutex>
#include <vector>

// Forward declarations
class CPeerManager;
typedef int NodeId;

// IBD Constants (used by ibd_coordinator)
static constexpr int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 32;  ///< Max individual blocks per peer (increased from 16 for better throughput)
static constexpr int BLOCK_STALL_TIMEOUT_SECONDS = 3;      ///< Stall timeout per block

/**
 * @file block_fetcher.h
 * @brief Block download manager for IBD
 *
 * CBlockFetcher is a thin wrapper around CBlockTracker (the SSOT for block tracking).
 * All actual tracking logic is delegated to CBlockTracker.
 *
 * This class provides:
 * - Integration with CPeerManager for peer statistics
 * - Simple API for the IBD coordinator
 */
class CBlockFetcher {
public:
    explicit CBlockFetcher(CPeerManager* peer_manager);
    ~CBlockFetcher() = default;

    // Disable copying
    CBlockFetcher(const CBlockFetcher&) = delete;
    CBlockFetcher& operator=(const CBlockFetcher&) = delete;

    /**
     * @brief Mark a block as received (by hash)
     * Delegates to CBlockTracker and updates CPeerManager stats.
     */
    bool MarkBlockReceived(NodeId peer, const uint256& hash);

    /**
     * @brief Get number of blocks waiting to be requested
     * Returns 0 - callers should check header_height vs chain_height
     */
    size_t GetPendingCount() const;

    /**
     * @brief Get number of blocks currently in-flight
     * Delegates to CBlockTracker::GetTotalInFlight()
     */
    size_t GetInFlightCount() const;

    /**
     * @brief Called when a peer connects (no-op, kept for API compatibility)
     */
    void OnPeerConnected(NodeId peer);

    // ============ Per-Block Download API (Bitcoin Core Style) ============

    /**
     * @brief Get next blocks that need to be requested
     * Returns heights from chain_height+1 to header_height that aren't in-flight.
     */
    std::vector<int> GetNextBlocksToRequest(int max_blocks, int chain_height, int header_height);

    /**
     * @brief Request a block from a specific peer
     * Delegates to CBlockTracker::AddBlock()
     */
    bool RequestBlockFromPeer(NodeId peer_id, int height, const uint256& hash);

    /**
     * @brief Called when a block is received (by height + hash)
     * Delegates to CBlockTracker::OnBlockReceivedByHeight()
     * Also updates peer's best known tip for fork divergence detection.
     */
    bool OnBlockReceived(NodeId peer_id, int height, const uint256& hash);

    /**
     * @brief Get blocks that have stalled (no response within timeout)
     * Delegates to CBlockTracker::CheckTimeouts()
     */
    std::vector<std::pair<int, NodeId>> GetStalledBlocks(std::chrono::seconds timeout);

    /**
     * @brief Remove a timed-out block from tracking
     * Delegates to CBlockTracker::RemoveTimedOut()
     */
    void RequeueBlock(int height);

    /**
     * @brief Get number of blocks in-flight for a peer
     * Delegates to CBlockTracker::GetPeerInFlightCount()
     */
    int GetPeerBlocksInFlight(NodeId peer_id) const;

    /**
     * @brief Check if a height is currently in-flight
     * Delegates to CBlockTracker::IsTracked()
     */
    bool IsHeightInFlight(int height) const;

    /**
     * @brief Clear all blocks above fork_point from tracking (for fork recovery)
     * Delegates to CBlockTracker::ClearAboveHeight()
     * @return Number of blocks removed
     */
    int ClearAboveHeight(int fork_point);

private:
    CPeerManager* m_peer_manager;

    // Statistics
    std::chrono::time_point<std::chrono::steady_clock> lastBlockReceived;
    int nBlocksReceivedTotal;

    // Phase 10 PR10.3 — fork-bias activation transition tracking.
    // Closes Phase 8 PR8.6-RT-MEDIUM-3 carryover (mechanism-vs-outcome
    // coverage gap for block_fetcher.cpp:109-124 fork-bias path).
    //
    // GetNextBlocksToRequest() is called on every download cycle (every
    // few seconds during IBD / fork resolution). Logging "fork-bias
    // activated" on every call would spam the log during fork
    // resolution. Instead, we log ONLY on transitions: log once when
    // fork_point first activates, log once again if fork_point changes
    // (different fork takes over), log once when fork-bias deactivates
    // (no active fork after one was active).
    //
    // Sentinel: -1 means "no fork-bias currently logged active";
    // any non-negative value is the last fork_point we logged.
    // Updated under cs_fetcher to avoid concurrent log-storm if multiple
    // threads call GetNextBlocksToRequest simultaneously.
    int m_last_fork_bias_logged_fork_point = -1;

    // Thread safety
    mutable std::mutex cs_fetcher;
};

#endif // DILITHION_NET_BLOCK_FETCHER_H
