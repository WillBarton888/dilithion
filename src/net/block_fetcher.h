// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_BLOCK_FETCHER_H
#define DILITHION_NET_BLOCK_FETCHER_H

#include <primitives/block.h>
#include <chrono>
#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <vector>

/**
 * @file block_fetcher.h
 * @brief Block download manager for parallel block fetching during IBD
 *
 * Implements Bitcoin Core-style block downloading:
 * 1. Parallel downloads from multiple peers (up to 16 blocks in-flight)
 * 2. Intelligent peer selection (fastest/most reliable peers)
 * 3. Timeout handling and retry (60 second timeout)
 * 4. Priority-based fetching (download in order by height)
 * 5. Stale tip detection (trigger header sync if stuck)
 * 6. DoS protection (rate limiting, peer scoring)
 *
 * This is Phase 3 of the IBD implementation (Bug #12).
 */

// Forward declarations
typedef int NodeId;

/**
 * @struct CBlockInFlight
 * @brief Tracks a block currently being downloaded
 */
struct CBlockInFlight {
    uint256 hash;                       ///< Block hash
    NodeId peer;                        ///< Peer downloading from
    std::chrono::time_point<std::chrono::steady_clock> timeRequested;  ///< When request was sent
    int nRetries;                       ///< Number of retry attempts
    int nHeight;                        ///< Block height (for priority sorting)

    CBlockInFlight()
        : peer(-1), nRetries(0), nHeight(0)
    {
        timeRequested = std::chrono::steady_clock::now();
    }

    CBlockInFlight(const uint256& hash_in, NodeId peer_in, int height_in)
        : hash(hash_in), peer(peer_in), nRetries(0), nHeight(height_in)
    {
        timeRequested = std::chrono::steady_clock::now();
    }
};

/**
 * @class CBlockFetcher
 * @brief Manages parallel block downloads during Initial Block Download (IBD)
 *
 * Thread-safe class for downloading blocks from multiple peers in parallel.
 * Handles timeouts, retries, peer selection, and download prioritization.
 *
 * Key features:
 * - Parallel downloads (16 blocks in-flight total, 8 per peer max)
 * - Timeout handling (60 second timeout with retry)
 * - Intelligent peer selection (fastest peers preferred)
 * - Priority queue (download blocks in height order)
 * - DoS protection (peer scoring and rate limiting)
 */
class CBlockFetcher {
public:
    CBlockFetcher();
    ~CBlockFetcher() = default;

    // Disable copying
    CBlockFetcher(const CBlockFetcher&) = delete;
    CBlockFetcher& operator=(const CBlockFetcher&) = delete;

    /**
     * @brief Queue a block for download
     *
     * Adds a block to the download queue. Higher priority blocks
     * (lower height) are downloaded first.
     *
     * @param hash Block hash to download
     * @param height Block height (for priority ordering)
     * @param announcing_peer Peer that announced this block (preferred for download)
     * @param highPriority If true, download immediately
     */
    void QueueBlockForDownload(const uint256& hash, int height,
                               NodeId announcing_peer = -1,
                               bool highPriority = false);

    /**
     * @brief Get the preferred peer for downloading a block
     *
     * Returns the peer that announced this block, if tracked.
     *
     * @param hash Block hash
     * @return Peer ID that announced this block, or -1 if not tracked
     */
    NodeId GetPreferredPeer(const uint256& hash) const;

    /**
     * @brief Request a block from a specific peer
     *
     * Sends GETDATA message to peer for this block.
     * Tracks the request as "in-flight" for timeout monitoring.
     *
     * @param peer Peer ID to request from
     * @param hash Block hash to request
     * @param height Block height
     * @return true if request sent successfully
     */
    bool RequestBlock(NodeId peer, const uint256& hash, int height);

    /**
     * @brief Mark a block as received
     *
     * Called when block is successfully downloaded.
     * Removes from in-flight tracking and updates peer statistics.
     *
     * @param peer Peer that sent the block
     * @param hash Block hash received
     * @return true if block was tracked as in-flight
     */
    bool MarkBlockReceived(NodeId peer, const uint256& hash);

    /**
     * @brief Get next blocks that should be fetched
     *
     * Determines which blocks to download next based on:
     * - Current download capacity (max 16 in-flight)
     * - Per-peer capacity (max 8 per peer)
     * - Available peers
     * - Block priority (height ordering)
     *
     * @param maxBlocks Maximum number of blocks to return
     * @return Vector of (hash, height) pairs to download
     */
    std::vector<std::pair<uint256, int>> GetNextBlocksToFetch(int maxBlocks = 16);

    /**
     * @brief Check for timed-out block requests
     *
     * Finds blocks that have been in-flight longer than timeout period.
     * Called periodically by main sync loop.
     *
     * @return Vector of hashes for timed-out blocks
     */
    std::vector<uint256> CheckTimeouts();

    /**
     * @brief Retry timed-out block requests
     *
     * Re-queues timed-out blocks for download, potentially from different peer.
     * Updates retry count and peer statistics (mark stall).
     *
     * @param timedOutHashes Vector of block hashes to retry
     */
    void RetryTimedOutBlocks(const std::vector<uint256>& timedOutHashes);

    /**
     * @brief Select best peer for downloading a block
     *
     * Chooses peer based on:
     * - Current load (blocks in-flight)
     * - Average response time (faster peers preferred)
     * - Stall count (avoid unreliable peers)
     * - Preferred peer status
     * - BUG #64: Announcing peer preference
     *
     * @param hash Block hash to download (unused currently, for future peer filtering)
     * @param preferred_peer BUG #64: Peer that announced this block (has priority)
     * @return Peer ID, or -1 if no suitable peer available
     */
    NodeId SelectPeerForDownload(const uint256& hash, NodeId preferred_peer = -1);

    /**
     * @brief Update peer statistics after download attempt
     *
     * Records download success/failure for peer selection algorithm.
     *
     * @param peer Peer ID
     * @param success true if download succeeded, false if failed/timed out
     * @param responseTime Time taken for download (milliseconds)
     */
    void UpdatePeerStats(NodeId peer, bool success, std::chrono::milliseconds responseTime = std::chrono::milliseconds(0));

    /**
     * @brief Check if a block is currently being downloaded
     *
     * @param hash Block hash to check
     * @return true if block is in-flight
     */
    bool IsDownloading(const uint256& hash) const;

    /**
     * @brief Check if a block is queued for download
     *
     * @param hash Block hash to check
     * @return true if block is in download queue
     */
    bool IsQueued(const uint256& hash) const;

    /**
     * @brief Get number of blocks currently in-flight
     *
     * @return Count of blocks being downloaded
     */
    int GetBlocksInFlight() const;

    /**
     * @brief Get number of blocks in-flight for a specific peer
     *
     * @param peer Peer ID
     * @return Count of blocks being downloaded from this peer
     */
    int GetBlocksInFlightForPeer(NodeId peer) const;

    /**
     * @brief Get list of all blocks waiting to be downloaded
     *
     * @return Vector of block hashes in download queue
     */
    std::vector<uint256> GetQueuedBlocks() const;

    /**
     * @brief Remove a block from download queue
     *
     * Called when block is obtained from another source (e.g., orphan pool)
     *
     * @param hash Block hash to remove
     */
    void RemoveFromQueue(const uint256& hash);

    /**
     * @brief Clear all download state for a peer
     *
     * Called when peer disconnects. Re-queues any in-flight blocks.
     *
     * @param peer Peer ID that disconnected
     */
    void OnPeerDisconnected(NodeId peer);

    /**
     * @brief Register a new peer
     *
     * Initializes download state for this peer.
     *
     * @param peer Peer ID
     */
    void OnPeerConnected(NodeId peer);

    /**
     * @brief Check if tip appears stale (no progress)
     *
     * Detects when IBD is stuck and needs header sync refresh.
     * Triggers if no new blocks received for 5 minutes.
     *
     * @return true if download appears stalled
     */
    bool IsStaleTip() const;

    /**
     * @brief Reset stale tip timer
     *
     * Called when new block received or header sync initiated.
     */
    void ResetStaleTipTimer();

    // Diagnostic/monitoring

    /**
     * @brief Get download statistics
     *
     * @return String with current download state
     */
    std::string GetDownloadStatus() const;

    /**
     * @brief Get average download speed
     *
     * @return Blocks per second
     */
    double GetDownloadSpeed() const;

    /**
     * @brief Clear all state (for testing)
     */
    void Clear();

private:
    // Phase 1 State Consolidation: PeerDownloadState removed - now tracked in CPeerManager::CPeer
    // All peer statistics (nBlocksInFlight, avgResponseTime, nStalls, etc.) are in CPeer

    /**
     * @struct BlockDownloadRequest
     * @brief Queued block download request with priority
     */
    struct BlockDownloadRequest {
        uint256 hash;
        int nHeight;
        NodeId announcing_peer;  // BUG #64: Track which peer announced this block
        bool highPriority;

        BlockDownloadRequest(const uint256& h, int height, NodeId peer = -1, bool priority = false)
            : hash(h), nHeight(height), announcing_peer(peer), highPriority(priority) {}

        // Priority queue ordering: high priority first, then by height (ascending)
        bool operator<(const BlockDownloadRequest& other) const {
            if (highPriority != other.highPriority)
                return !highPriority;  // High priority comes first
            return nHeight > other.nHeight;  // Lower height (earlier blocks) first
        }
    };

    // Download tracking
    std::map<uint256, CBlockInFlight> mapBlocksInFlight;     ///< Hash -> In-flight info
    std::map<NodeId, std::set<uint256>> mapPeerBlocks;       ///< Peer -> Blocks in-flight
    std::priority_queue<BlockDownloadRequest> queueBlocksToFetch;  ///< Priority queue of blocks to download
    std::set<uint256> setQueuedHashes;                       ///< Fast lookup for queued blocks
    std::map<uint256, NodeId> mapPreferredPeers;             ///< BUG #64: Block -> Announcing peer

    // Phase 1: Peer tracking removed - now in CPeerManager exclusively

    // Stale tip detection
    std::chrono::time_point<std::chrono::steady_clock> lastBlockReceived;  ///< Last successful download
    int nBlocksReceivedTotal;                                ///< Total blocks received

    // Configuration
    // BUG #147 FIX: Match Bitcoin Core's IBD parameters
    static constexpr int MAX_BLOCKS_IN_FLIGHT = 128;         ///< Max total blocks downloading (Bitcoin Core: 128)
    static constexpr int MAX_BLOCKS_PER_PEER = 16;           ///< Max blocks per peer
    static constexpr auto BLOCK_DOWNLOAD_TIMEOUT = std::chrono::seconds(60);  ///< Timeout per block
    static constexpr auto STALE_TIP_TIMEOUT = std::chrono::minutes(5);        ///< Time before tip considered stale
    static constexpr int MAX_RETRIES = 3;                    ///< Max retry attempts per block
    static constexpr int PEER_STALL_THRESHOLD = 10;          ///< BUG #61: Stalls before peer avoided (raised from 5)
    static constexpr auto PEER_STALL_TIMEOUT = std::chrono::minutes(5);  ///< BUG #61: Forgive stalls after this time

    // Thread safety
    mutable std::mutex cs_fetcher;                           ///< Protects all data members

    // Internal helpers

    /**
     * @brief Get available download slots
     *
     * @return Number of additional blocks that can be requested
     */
    int GetAvailableSlots() const;

    // Phase 1: GetAvailableSlotsForPeer, MarkPeerStalled, IsPeerSuitable moved to CPeerManager
    // CBlockFetcher now delegates all peer management to CPeerManager

    /**
     * @brief Update download speed tracking
     */
    void UpdateDownloadSpeed();
};

#endif // DILITHION_NET_BLOCK_FETCHER_H
