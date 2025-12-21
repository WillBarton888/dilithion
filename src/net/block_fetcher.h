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
static constexpr int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;  ///< Max individual blocks per peer
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
     * @brief Called when a block is received (by height)
     * Delegates to CBlockTracker::OnBlockReceivedByHeight()
     */
    bool OnBlockReceived(NodeId peer_id, int height);

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

private:
    CPeerManager* m_peer_manager;

    // Statistics
    std::chrono::time_point<std::chrono::steady_clock> lastBlockReceived;
    int nBlocksReceivedTotal;

    // Thread safety
    mutable std::mutex cs_fetcher;
};

#endif // DILITHION_NET_BLOCK_FETCHER_H
