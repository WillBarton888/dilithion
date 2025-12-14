// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_BLOCK_FETCHER_H
#define DILITHION_NET_BLOCK_FETCHER_H

#include <primitives/block.h>
#include <chrono>
#include <functional>
#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <vector>
#include <sstream>

// Forward declaration for dependency injection
class CPeerManager;

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
 * Bitcoin Core IBD Constants
 *
 * These values match Bitcoin Core defaults for proven performance:
 * - 16 blocks/chunk: Small enough for fast stall detection, large enough for efficiency
 * - 2 second timeout: Aggressive stall detection (Bitcoin Core default)
 * - 4 chunks per peer: Allows 64 blocks in-flight per peer (16 * 4)
 */
static constexpr int BLOCK_DOWNLOAD_WINDOW_SIZE = 1024;  ///< Max blocks in download queue
static constexpr int MAX_BLOCKS_PER_CHUNK = 16;          ///< Blocks per chunk (Bitcoin Core: 16)
static constexpr int CHUNK_STALL_TIMEOUT_SECONDS = 15;   ///< IBD HANG FIX #4: Increased to 15s for better tolerance of cross-region peers and slow networks
static constexpr int MAX_CHUNKS_PER_PEER = 4;            ///< Max concurrent chunks per peer (16 * 4 = 64 blocks)
static constexpr int MAX_CHUNK_STALL_COUNT = 50;         ///< Max stalls before peer avoided

/**
 * @struct PeerChunk
 * @brief Tracks a chunk of consecutive blocks assigned to a single peer
 *
 * Bitcoin Core's key insight: assign CONSECUTIVE blocks to SAME peer.
 * This ensures blocks arrive in order, eliminating orphan blocks.
 *
 * Example: Peer 1 gets blocks 1-16, Peer 2 gets blocks 17-32, etc.
 * When Peer 1's blocks arrive, they're all sequential and connect immediately.
 */
struct PeerChunk {
    NodeId peer_id;                     ///< Peer assigned to this chunk
    int height_start;                   ///< First block height in chunk
    int height_end;                     ///< Last block height in chunk (inclusive)
    int blocks_pending;                 ///< Blocks not yet received
    int blocks_received;                ///< Blocks successfully received
    std::chrono::steady_clock::time_point assigned_time;   ///< When chunk was assigned
    std::chrono::steady_clock::time_point last_activity;   ///< Last block received

    PeerChunk()
        : peer_id(-1), height_start(0), height_end(0), blocks_pending(0), blocks_received(0)
    {
        assigned_time = std::chrono::steady_clock::now();
        last_activity = assigned_time;
    }

    PeerChunk(NodeId peer, int start, int end)
        : peer_id(peer), height_start(start), height_end(end),
          blocks_pending(end - start + 1), blocks_received(0)
    {
        assigned_time = std::chrono::steady_clock::now();
        last_activity = assigned_time;
    }

    int ChunkSize() const { return height_end - height_start + 1; }
    bool IsComplete() const { return blocks_pending == 0; }
};

/**
 * @class CBlockDownloadWindow
 * @brief Manages the 1024-block sliding window for IBD downloads
 *
 * Bitcoin Core pattern: Only maintain up to 1024 blocks in the download pipeline.
 * This prevents memory exhaustion while keeping download throughput high.
 *
 * Block states:
 * - PENDING: In window but not yet requested
 * - IN_FLIGHT: Requested from peer, awaiting response
 * - RECEIVED: Downloaded but not yet connected to chain
 * - CONNECTED: Successfully added to active chain
 */
class CBlockDownloadWindow {
public:
    static constexpr int WINDOW_SIZE = BLOCK_DOWNLOAD_WINDOW_SIZE;  ///< 1024 blocks max

    CBlockDownloadWindow() : m_window_start(0), m_target_height(0) {}

    /**
     * @brief Initialize window with sync target
     * @param chain_height Current chain height
     * @param target_height Target height to sync to
     */
    void Initialize(int chain_height, int target_height) {
        m_window_start = chain_height + 1;
        m_target_height = target_height;
        m_pending.clear();
        // IBD HANG FIX #20: Removed m_in_flight tracking - CPeerManager is single source of truth
        m_received.clear();

        // Populate pending with initial window
        int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
        for (int h = m_window_start; h <= window_end; h++) {
            m_pending.insert(h);
        }
    }

    /**
     * @brief Mark heights as requested (removes from pending)
     * @param heights Vector of heights being requested
     * IBD HANG FIX #20: No longer tracks in-flight locally - CPeerManager is single source of truth
     */
    void MarkAsInFlight(const std::vector<int>& heights) {
        for (int h : heights) {
            m_pending.erase(h);
            // IBD HANG FIX #20: Don't add to m_in_flight - CPeerManager tracks this
        }
    }

    /**
     * @brief Mark height as received (moved from pending to received)
     * @param height Height of received block
     * IBD HANG FIX #20: No longer clears m_in_flight - CPeerManager is single source of truth
     */
    void OnBlockReceived(int height) {
        // IBD HANG FIX #18: Also remove from pending (block may arrive before marked in-flight)
        // Without this, heights get stuck in pending when blocks arrive quickly
        m_pending.erase(height);
        // IBD HANG FIX #20: Don't erase from m_in_flight - CPeerManager handles this
        m_received.insert(height);
    }

    /**
     * @brief Mark height as connected to chain (removed from tracking)
     * @param height Height of connected block
     * @param is_height_queued_callback Optional callback to check if height is queued for validation
     *                                  IBD HANG FIX #2: Allows window to advance past queued blocks
     * @param is_height_in_flight_callback Optional callback to check if height is in-flight
     *                                     IBD STUCK FIX #6: Prevents window from advancing past in-flight heights
     * IBD HANG FIX #20: No longer clears m_in_flight - CPeerManager is single source of truth
     */
    void OnBlockConnected(int height,
                          std::function<bool(int)> is_height_queued_callback = nullptr,
                          std::function<bool(int)> is_height_in_flight_callback = nullptr) {
        m_received.erase(height);
        m_pending.erase(height);  // In case we never received it
        // IBD HANG FIX #20: Don't erase from m_in_flight - CPeerManager handles this

        // IBD BOTTLENECK FIX #1: Advance window whenever ANY block in window is connected
        // Previously only advanced when height == m_window_start, causing stalls with out-of-order blocks
        // Now advances past all connected blocks, allowing window to slide forward continuously
        if (IsInWindow(height)) {
            AdvanceWindow(is_height_queued_callback, is_height_in_flight_callback);
        }
    }

    /**
     * @brief Mark height as pending for re-request (used when cancelling stalled chunks)
     * @param height Height to mark as pending
     * IBD HANG FIX #20: No longer clears m_in_flight - CPeerManager is single source of truth
     */
    void MarkAsPending(int height) {
        if (IsInWindow(height)) {
            // IBD HANG FIX #20: Don't erase from m_in_flight - CPeerManager handles this
            m_received.erase(height);
            m_pending.insert(height);
        }
    }
    
    /**
     * @brief Add height to pending set (used when queueing new blocks)
     * IBD SLOW FIX #3: Allows external code to add heights to pending set
     * @param height Height to add to pending
     * IBD HANG FIX #20: No longer checks m_in_flight - CPeerManager is single source of truth
     */
    void AddToPending(int height) {
        // IBD SLOW FIX #3: Expand window automatically if height is outside range
        // This prevents heights from being silently ignored when outside window range
        if (height >= m_window_start + WINDOW_SIZE && height <= m_target_height) {
            // Height is beyond current window but within target - expand window
            int new_window_start = std::max(m_window_start, height - WINDOW_SIZE + 1);
            // Advance window start to include this height
            while (m_window_start < new_window_start && m_window_start <= m_target_height) {
                // Remove old heights from tracking sets as window advances
                m_pending.erase(m_window_start);
                // IBD HANG FIX #20: Don't erase from m_in_flight - CPeerManager handles this
                m_received.erase(m_window_start);
                m_window_start++;
            }
        }

        // Only add if within window range and not already tracked locally
        // IBD HANG FIX #20: No longer check m_in_flight - CPeerManager is single source of truth
        if (IsInWindow(height) &&
            m_pending.count(height) == 0 &&
            m_received.count(height) == 0) {
            m_pending.insert(height);
        }
    }

    /**
     * @brief Get next chunk of heights that need to be requested
     * IBD SLOW FIX #1: Ensure consecutive heights are returned for efficient chunk assignment
     * @param max_count Maximum heights to return
     * @return Vector of consecutive heights from pending set
     */
    std::vector<int> GetNextPendingHeights(int max_count) const {
        std::vector<int> result;
        result.reserve(max_count);

        // IBD SLOW FIX #1: Return consecutive heights starting from window_start
        // This ensures chunks are assigned efficiently without gaps
        // Previously iterated through set (sorted but might have gaps)
        // Now starts from window_start and finds consecutive heights
        
        int start_height = m_window_start;
        int consecutive_count = 0;
        
        // Try to find consecutive heights starting from window_start
        for (int h = start_height; h <= m_target_height && consecutive_count < max_count; h++) {
            if (m_pending.count(h) > 0) {
                result.push_back(h);
                consecutive_count++;
            } else if (!result.empty()) {
                // Found a gap - stop here to maintain consecutiveness
                // Next call will start from this height
                break;
            }
            // If result is empty and h not in pending, continue searching
        }
        
        // Fallback: If no consecutive heights found, return any heights (original behavior)
        if (result.empty()) {
            for (int h : m_pending) {
                if (static_cast<int>(result.size()) >= max_count) break;
                result.push_back(h);
            }
        }

        return result;
    }

    // State queries
    bool IsInWindow(int height) const {
        return height >= m_window_start && height < m_window_start + WINDOW_SIZE;
    }

    bool IsPending(int height) const { return m_pending.count(height) > 0; }
    // IBD HANG FIX #20: No longer track in-flight locally - CPeerManager is single source of truth
    // This method returns false; callers should use CPeerManager::IsBlockInFlight() for accurate info
    bool IsInFlight(int height) const { (void)height; return false; }
    bool IsReceived(int height) const { return m_received.count(height) > 0; }

    int GetWindowStart() const { return m_window_start; }
    int GetWindowEnd() const { return std::min(m_window_start + WINDOW_SIZE - 1, m_target_height); }
    int GetTargetHeight() const { return m_target_height; }

    size_t PendingCount() const { return m_pending.size(); }
    // IBD HANG FIX #20: No longer track in-flight locally - CPeerManager is single source of truth
    // Returns 0; callers should use CPeerManager::GetTotalBlocksInFlight() for accurate count
    size_t InFlightCount() const { return 0; }
    size_t ReceivedCount() const { return m_received.size(); }

    bool IsComplete() const { return m_window_start > m_target_height; }

    std::string GetStatus() const {
        std::ostringstream ss;
        ss << "Window [" << m_window_start << "-" << GetWindowEnd() << "/" << m_target_height << "] "
           << "pending=" << m_pending.size()
           << " received=" << m_received.size();
        // IBD HANG FIX #20: No longer show flight count - CPeerManager is single source of truth
        return ss.str();
    }

    /**
     * @brief IBD HANG FIX #15: Update target height when headers grow
     *
     * During IBD, new headers continue arriving while blocks are being downloaded.
     * The window target must be updated to include these new heights, otherwise
     * the window becomes "complete" prematurely and no new heights are requested.
     *
     * @param new_target_height New target height (typically current header height)
     * @return true if target was updated, false if unchanged
     * IBD HANG FIX #20: No longer checks m_in_flight - CPeerManager is single source of truth
     */
    bool UpdateTargetHeight(int new_target_height) {
        if (new_target_height <= m_target_height) {
            return false;  // Target unchanged or decreased
        }

        int old_target = m_target_height;
        m_target_height = new_target_height;

        // If window was "complete" (window_start > old_target), we need to add
        // new heights to pending to resume downloading
        if (m_window_start > old_target) {
            // Window had advanced past old target, but now there's more to download
            // Add heights from window_start to new window_end as pending
            // IBD HANG FIX #20: No longer check m_in_flight - CPeerManager is single source of truth
            int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
            for (int h = m_window_start; h <= window_end; h++) {
                if (m_pending.count(h) == 0 && m_received.count(h) == 0) {
                    m_pending.insert(h);
                }
            }
        }

        return true;
    }

private:
    void AdvanceWindow(std::function<bool(int)> is_height_queued_callback = nullptr,
                       std::function<bool(int)> is_height_in_flight_callback = nullptr) {
        // IBD HANG FIX #2: Allow window advancement past queued blocks
        // IBD HANG FIX #5: Better window state tracking - distinguish "processing" vs "stuck"
        // IBD HANG FIX #20: No longer check m_in_flight - CPeerManager is single source of truth
        // IBD STUCK FIX #6: Check CPeerManager for in-flight status before advancing
        // Window can advance if height is not pending, received, or in-flight

        while (m_window_start <= m_target_height) {
            bool can_advance = false;

            // IBD STUCK FIX #6: Check if height is in-flight via callback (CPeerManager)
            // Without this check, window advances past heights that are still being fetched
            // This causes gaps where heights 17-256 are skipped when chunks timeout
            bool is_in_flight = false;
            if (is_height_in_flight_callback) {
                is_in_flight = is_height_in_flight_callback(m_window_start);
            }

            // Can advance if height is not in local tracking sets AND not in-flight
            // IBD STUCK FIX #6: Added is_in_flight check to prevent advancing past fetching heights
            if (m_pending.count(m_window_start) == 0 &&
                m_received.count(m_window_start) == 0 &&
                !is_in_flight) {
                can_advance = true;
            }
            // IBD HANG FIX #2: Also advance if height is in "received" but queued for validation
            // This means it's being processed (not stuck), so window can advance
            else if (m_received.count(m_window_start) > 0 && is_height_queued_callback) {
                if (is_height_queued_callback(m_window_start)) {
                    // Block is queued for validation - it's being processed, allow advancement
                    can_advance = true;
                    // Remove from received since we're advancing past it
                    m_received.erase(m_window_start);
                }
            }

            if (can_advance) {
                m_window_start++;
            } else {
                // Can't advance further - this height is still being processed, in-flight, or stuck
                break;
            }
        }

        // Add new heights to pending to fill window
        // IBD HANG FIX #20: No longer check m_in_flight - CPeerManager is single source of truth
        int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
        for (int h = m_window_start; h <= window_end; h++) {
            if (m_pending.count(h) == 0 && m_received.count(h) == 0) {
                m_pending.insert(h);
            }
        }
    }

    int m_window_start;      ///< First height in window
    int m_target_height;     ///< Final sync target

    std::set<int> m_pending;     ///< Heights not yet requested
    // IBD HANG FIX #20: Removed m_in_flight - CPeerManager is single source of truth for in-flight blocks
    std::set<int> m_received;    ///< Heights received, not yet connected
};

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
    explicit CBlockFetcher(CPeerManager* peer_manager);
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
     * @brief BUG #158: Get number of blocks in download queue (pending)
     *
     * @return Count of blocks waiting to be requested
     */
    size_t GetPendingCount() const;

    /**
     * @brief BUG #158: Get number of blocks currently in-flight (for fork detection)
     *
     * @return Count of blocks being downloaded
     */
    size_t GetInFlightCount() const;

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

    // ============ Phase 2: Sequential Chunk Assignment ============

    /**
     * @brief Assign a chunk of consecutive blocks to a peer
     *
     * Bitcoin Core-style: assign CONSECUTIVE heights to SAME peer.
     * This ensures blocks arrive in order, eliminating orphan blocks.
     *
     * @param peer_id Peer to assign chunk to
     * @param height_start First block height in chunk
     * @param height_end Last block height in chunk (inclusive)
     * @return true if chunk was assigned successfully
     */
    bool AssignChunkToPeer(NodeId peer_id, int height_start, int height_end);

    /**
     * @brief Get the next chunk of consecutive heights to download
     *
     * Finds up to MAX_BLOCKS_PER_CHUNK (16) consecutive heights that:
     * - Are not already in-flight
     * - Are not already assigned to another peer
     * - Start from the lowest unassigned height
     *
     * @param max_blocks Maximum blocks in chunk (default: 16)
     * @return Vector of heights to assign
     */
    std::vector<int> GetNextChunkHeights(int max_blocks = MAX_BLOCKS_PER_CHUNK);

    /**
     * @brief Mark a height as received, update chunk tracking
     *
     * @param height Block height received
     * @return Peer ID that had this height assigned, or -1 if not tracked
     */
    NodeId OnChunkBlockReceived(int height);

    /**
     * @brief Check for stalled chunks (no activity > CHUNK_STALL_TIMEOUT_SECONDS)
     *
     * @return Vector of (peer_id, chunk) pairs that are stalled
     */
    std::vector<std::pair<NodeId, PeerChunk>> CheckStalledChunks();

    /**
     * @brief Reassign a stalled chunk to a different peer
     *
     * @param old_peer Original peer ID
     * @param new_peer New peer ID to assign chunk to
     * @return true if reassignment successful
     */
    bool ReassignChunk(NodeId old_peer, NodeId new_peer);

    /**
     * @brief Clean up cancelled chunks after grace period expires
     *
     * IBD HANG FIX: Removes cancelled chunks and their height mappings after grace period.
     * Called periodically to clean up chunks that were cancelled but blocks never arrived.
     */
    void CleanupCancelledChunks();

    /**
     * @brief Cancel a stalled chunk, making heights available for re-request
     *
     * Call this when a chunk cannot be reassigned to another peer (e.g., all
     * peers have active chunks). Moves chunk to cancelled map (grace period) instead of
     * immediately erasing, allowing blocks that arrive late to be properly tracked.
     *
     * IBD HANG FIX: Keeps heights in mapHeightToPeer during grace period to handle
     * race condition where blocks arrive after cancellation.
     *
     * @param peer_id Peer whose chunk should be cancelled
     * @return true if chunk was cancelled
     */
    bool CancelStalledChunk(NodeId peer_id);

    /**
     * @brief Update chunk activity timestamp (call after sending GETDATA)
     *
     * BUG #155 FIX: Prevents false stall detection when network is slow.
     * Call this immediately after successfully sending GETDATA for a chunk.
     *
     * @param peer_id Peer ID to update
     */
    void UpdateChunkActivity(NodeId peer_id);

    /**
     * @brief Get the peer assigned to download a specific height
     *
     * @param height Block height
     * @return Peer ID, or -1 if height not assigned
     */
    NodeId GetPeerForHeight(int height) const;

    /**
     * @brief Get active chunk for a peer
     *
     * @param peer_id Peer ID
     * @return Pointer to chunk, or nullptr if peer has no active chunk
     */
    const PeerChunk* GetPeerChunk(NodeId peer_id) const;

    /**
     * @brief Get statistics on current chunk assignments
     *
     * @return String with chunk status
     */
    std::string GetChunkStatus() const;

    // ============ Phase 3: Moving Window Public Methods ============

    /**
     * @brief Initialize the download window for IBD
     *
     * Called when starting IBD to set up the 1024-block sliding window.
     *
     * @param chain_height Current chain height
     * @param target_height Target sync height (header height)
     */
    void InitializeWindow(int chain_height, int target_height);

    /**
     * @brief Get next heights from the window that need to be requested
     *
     * Returns heights that are in PENDING state (not yet in-flight or received).
     * Respects the 1024-block window limit.
     *
     * @param max_count Maximum heights to return
     * @return Vector of heights ready for download
     */
    std::vector<int> GetWindowPendingHeights(int max_count);

    /**
     * @brief Mark heights as in-flight in the window
     *
     * Called after requesting blocks from a peer.
     *
     * @param heights Heights being requested
     */
    void MarkWindowHeightsInFlight(const std::vector<int>& heights);

    /**
     * @brief Mark a height as received in the window
     *
     * @param height Height of received block
     */
    void OnWindowBlockReceived(int height);

    /**
     * @brief Mark a height as connected to chain
     *
     * Advances the window if this was the start.
     *
     * @param height Height of connected block
     */
    void OnWindowBlockConnected(int height);

    /**
     * @brief Add heights to window's pending set
     *
     * IBD SLOW FIX #3: Allows QueueMissingBlocks() to add heights to window
     * instead of just the old priority queue. This synchronizes the two systems.
     *
     * @param heights Heights to add to pending set (if within window range)
     */
    void AddHeightsToWindowPending(const std::vector<int>& heights);

    /**
     * @brief Check if the download window has been initialized
     *
     * @return true if InitializeWindow() has been called
     */
    bool IsWindowInitialized() const;

    /**
     * @brief Get current window status string
     *
     * @return Status string with window metrics
     */
    std::string GetWindowStatus() const;

    /**
     * @brief Check if all blocks in window have been synced
     *
     * @return true if window_start > target_height
     */
    bool IsWindowComplete() const;

    /**
     * @brief IBD HANG FIX #15: Update window target height when headers grow
     *
     * Call this periodically during IBD to update the target height as new
     * headers are received. This prevents the window from becoming "complete"
     * prematurely when there are more blocks to download.
     *
     * @param new_target_height New target height (current header height)
     * @return true if target was updated, false if unchanged
     */
    bool UpdateWindowTarget(int new_target_height);

private:
    CPeerManager* m_peer_manager;  // Single source of truth - no global dependency

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

    // ============ Phase 2: Chunk Tracking State ============
    std::map<NodeId, PeerChunk> mapActiveChunks;   ///< Peer -> Active chunk
    std::map<int, NodeId> mapHeightToPeer;         ///< Height -> Assigned peer
    int nNextChunkHeight{0};                       ///< Next height to start a chunk from
    
    // IBD HANG FIX: Track cancelled chunks during grace period
    // Prevents race condition where blocks arrive after chunk cancellation
    struct CancelledChunk {
        PeerChunk chunk;
        std::chrono::steady_clock::time_point cancelled_time;
        CancelledChunk() : chunk(), cancelled_time(std::chrono::steady_clock::now()) {}
        CancelledChunk(const PeerChunk& c) : chunk(c), cancelled_time(std::chrono::steady_clock::now()) {}
    };
    std::map<NodeId, CancelledChunk> mapCancelledChunks;  ///< Peer -> Cancelled chunk (grace period)
    static constexpr int CANCELLED_CHUNK_GRACE_PERIOD_SECONDS = 30;  ///< Keep cancelled chunks for 30s

    // ============ Phase 3: Moving Window ============
    CBlockDownloadWindow m_download_window;        ///< 1024-block sliding window
    bool m_window_initialized{false};              ///< Whether window has been initialized

    // Stale tip detection
    std::chrono::time_point<std::chrono::steady_clock> lastBlockReceived;  ///< Last successful download
    int nBlocksReceivedTotal;                                ///< Total blocks received

    // Configuration
    // BUG #147 FIX: Match Bitcoin Core's IBD parameters
    static constexpr int MAX_BLOCKS_IN_FLIGHT = 128;         ///< Max total blocks downloading (Bitcoin Core: 128)
    // IBD FIX #11: Increased from 16 to 64 for high-latency single-peer IBD
    static constexpr int MAX_BLOCKS_PER_PEER = 64;           ///< Max blocks per peer
    // IBD HANG FIX #9: Increase block timeout to 120s for cross-region IBD
    // Previously 60s was too short - blocks would timeout before arriving over slow links
    // Then CheckStalledChunks() would see "no blocks in-flight" and cancel the chunk
    // 120s allows sufficient time for cross-region block delivery
    static constexpr auto BLOCK_DOWNLOAD_TIMEOUT = std::chrono::seconds(120);  ///< Timeout per block
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
