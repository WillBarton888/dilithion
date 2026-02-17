// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_IBD_COORDINATOR_H
#define DILITHION_NODE_IBD_COORDINATOR_H

#include <atomic>
#include <chrono>
#include <set>
#include <string>

// Forward declarations
class CChainState;
class NodeContext;

/**
 * @brief IBD State Machine
 *
 * Phase 5.1: State machine for tracking IBD phases
 */
enum class IBDState {
    IDLE,              // No IBD needed (chain is synced)
    WAITING_FOR_PEERS, // Waiting for peers to connect
    HEADERS_SYNC,      // Syncing headers from peers
    BLOCKS_DOWNLOAD,   // Downloading blocks
    COMPLETE           // IBD complete
};

/**
 * @brief Fork recovery reason codes (A2: structured observability)
 *
 * Used for structured logging and metrics when fork recovery is triggered.
 */
enum class ForkRecoveryReason {
    LAYER1_TIP_MISMATCH,    // Layer 1: Our tip hash doesn't match header chain
    LAYER2_ORPHAN_STREAK,   // Layer 2: Consecutive orphan blocks exceeded threshold
    LAYER3_STALL_TIMEOUT,   // Layer 3: Chain stalled with IBD activity
};

inline const char* ForkRecoveryReasonToString(ForkRecoveryReason reason) {
    switch (reason) {
        case ForkRecoveryReason::LAYER1_TIP_MISMATCH: return "LAYER1_TIP_MISMATCH";
        case ForkRecoveryReason::LAYER2_ORPHAN_STREAK: return "LAYER2_ORPHAN_STREAK";
        case ForkRecoveryReason::LAYER3_STALL_TIMEOUT: return "LAYER3_STALL_TIMEOUT";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Encapsulates the Initial Block Download coordination logic.
 *
 * Phase 5.1: Encapsulates IBD logic from main loop
 * 
 * Dilithion originally embedded all block download orchestration inside
 * the main node loop.  This class collects the state (backoff counters,
 * header deltas) and exposes a single Tick() entry point, mirroring the
 * structure used by Bitcoin Core's net_processing loop.
 */
class CIbdCoordinator {
public:
    /**
     * @brief Constructor using NodeContext (Phase 5.1)
     * 
     * Uses NodeContext to access all required components, following
     * the pattern established in Phase 1.2.
     */
    CIbdCoordinator(CChainState& chainstate, NodeContext& node_context);

    /**
     * @brief Executes one maintenance pass of block download coordination.
     *
     * Call this from the main event loop once per second.  It handles:
     *  - State machine transitions
     *  - Exponential backoff when no peers are available.
     *  - Queueing headers-ahead blocks for download.
     *  - Dispatching GETDATA requests up to the in-flight limit.
     *  - Retrying timed-out blocks and disconnecting stalling peers.
     */
    void Tick();

    /**
     * @brief Get current IBD state
     */
    IBDState GetState() const { return m_state; }

    /**
     * @brief Get human-readable state name
     */
    std::string GetStateName() const;

    /**
     * @brief Check if IBD is active (not IDLE or COMPLETE)
     */
    bool IsActive() const {
        return m_state != IBDState::IDLE && m_state != IBDState::COMPLETE;
    }

    /**
     * @brief Check if node is synced with the network (not in IBD)
     *
     * Thread-safe. Returns true when the node's chain is within
     * SYNC_TOLERANCE_BLOCKS of the best known header height.
     *
     * Uses hysteresis to prevent state flapping:
     * - Becomes synced when within SYNC_TOLERANCE_BLOCKS of headers
     * - Becomes un-synced when more than UNSYNC_THRESHOLD_BLOCKS behind
     *
     * This method is designed to be called from any thread, including
     * header validation workers. The atomic m_synced flag ensures
     * thread-safe reads without locking.
     */
    bool IsSynced() const;

    /**
     * @brief Check if node is in Initial Block Download
     *
     * Inverse of IsSynced(). Returns true when the node is still
     * catching up to the network and should not mine or relay transactions.
     */
    bool IsInitialBlockDownload() const;

    /**
     * @brief Called when an orphan block is received (Layer 2 fork detection)
     *
     * Consecutive orphan blocks during IBD suggest we may be on a fork.
     * After ORPHAN_FORK_THRESHOLD consecutive orphans, triggers fork detection.
     */
    void OnOrphanBlockReceived() {
        m_consecutive_orphan_blocks.fetch_add(1);
    }

    /**
     * @brief Called when a block successfully connects to the chain
     *
     * Resets the orphan counter since the chain is progressing normally.
     * Also updates block-flow timestamp for Layer 3 flow-aware gating (B3).
     */
    void OnBlockConnected() {
        m_consecutive_orphan_blocks.store(0);
        m_last_block_connected_ticks.store(
            std::chrono::steady_clock::now().time_since_epoch().count());
    }

    /**
     * @brief Check if reindex is required due to deep fork
     */
    bool RequiresReindex() const { return m_requires_reindex; }

private:
    void UpdateState();
    void ResetBackoffOnNewHeaders(int header_height);
    bool ShouldAttemptDownload() const;
    double GetDownloadRateMultiplier() const;  // IBD HANG FIX #1: Gradual backpressure (0.0-1.0)
    void HandleNoPeers(std::chrono::steady_clock::time_point now);
    void DownloadBlocks(int header_height, int chain_height, std::chrono::steady_clock::time_point now);
    bool FetchBlocks();
    void RetryTimeoutsAndStalls();

    // BUG #158 FIX: Fork detection and recovery
    int FindForkPoint(int chain_height);
    void HandleForkScenario(int fork_point, int chain_height);

    /**
     * @brief Attempt fork recovery: find fork point, validate chainwork, create ForkCandidate
     *
     * Unified recovery pipeline for all layers (A2/B1).
     * Returns true if a fork candidate was created or is already active.
     */
    bool AttemptForkRecovery(int chain_height, int header_height,
                             ForkRecoveryReason reason = ForkRecoveryReason::LAYER3_STALL_TIMEOUT);

    // Headers sync peer management (Bitcoin Core style)
    void SelectHeadersSyncPeer();           // Pick a sync peer if none selected
    bool CheckHeadersSyncProgress();        // Check if sync peer is making progress
    void SwitchHeadersSyncPeer();           // Switch to a different peer

    // IBD HANG FIX #6: Hang cause tracking
    enum class HangCause {
        NONE,
        VALIDATION_QUEUE_FULL,
        NO_PEERS_AVAILABLE,
        PEERS_AT_CAPACITY
    };
    HangCause GetLastHangCause() const { return m_last_hang_cause; }

    CChainState& m_chainstate;
    NodeContext& m_node_context;

    // State machine
    IBDState m_state{IBDState::IDLE};

    // Sync state tracking (thread-safe)
    // Uses hysteresis to prevent flapping between synced/not-synced states
    std::atomic<bool> m_synced{false};
    static constexpr int SYNC_TOLERANCE_BLOCKS = 2;   // Become synced when within N blocks
    static constexpr int UNSYNC_THRESHOLD_BLOCKS = 10; // Become un-synced when N+ blocks behind

    // Headers sync peer tracking (Bitcoin Core style single-sync-peer)
    int m_headers_sync_peer{-1};                                    // NodeId of current sync peer (-1 = none)
    std::chrono::steady_clock::time_point m_headers_sync_timeout;   // When to consider sync peer stalled
    int m_headers_sync_last_height{0};                              // Header height at last progress check
    uint64_t m_headers_sync_last_processed{0};                      // Processed count at last progress check (fork catch-up)
    bool m_headers_in_flight{false};                                // True while awaiting headers from sync peer
    static constexpr int HEADERS_SYNC_TIMEOUT_BASE_SECS = 45;       // 45 sec base timeout (faster failover)
    static constexpr int HEADERS_SYNC_TIMEOUT_PER_HEADER_MS = 1;    // +1ms per missing header
    std::set<int> m_headers_bad_peers;                              // Peers that have repeatedly failed to deliver headers
    int m_headers_sync_peer_consecutive_stalls{0};                  // Consecutive stalls for current peer
    static constexpr int MAX_HEADERS_CONSECUTIVE_STALLS = 3;        // Ban peer after N consecutive stalls

    // Blocks sync peer tracking (single peer for block download, different from headers peer)
    int m_blocks_sync_peer{-1};                                     // NodeId of block sync peer (-1 = none)
    int m_blocks_sync_peer_consecutive_timeouts{0};                 // Consecutive 60s timeout cycles without delivery
    static constexpr int MAX_PEER_CONSECUTIVE_TIMEOUTS = 3;         // Force reselection after N consecutive timeouts
    // BUG #256: Track timed-out peers to avoid re-selecting them immediately
    int m_timed_out_peer{-1};                                       // Peer that timed out (excluded from selection)
    std::chrono::steady_clock::time_point m_timed_out_peer_time;    // When the peer timed out
    static constexpr int TIMED_OUT_PEER_COOLDOWN_SEC = 3600;        // 1 hour cooldown (Bitcoin-style penalty)

    // Capacity stall detection: if peer is "at capacity" for too long without blocks arriving,
    // clear in-flight blocks and force peer reselection (much faster than 60s hard timeout)
    int m_consecutive_capacity_stalls{0};
    static constexpr int MAX_CAPACITY_STALLS_BEFORE_CLEAR = 15;  // 15 seconds of stalling

    // Backoff state
    int m_last_header_height{0};
    int m_ibd_no_peer_cycles{0};
    std::chrono::steady_clock::time_point m_last_ibd_attempt;
    
    // IBD HANG FIX #6: Hang cause tracking
    mutable HangCause m_last_hang_cause{HangCause::NONE};

    // BUG #158 FIX: Fork detection state
    // THREAD SAFETY FIX: Using atomic for thread-safe access
    std::atomic<int> m_fork_stall_cycles{0};  // Cycles where blocks aren't connecting
    std::atomic<bool> m_fork_detected{false}; // Whether we've detected a fork
    std::atomic<int> m_fork_point{-1};        // Height of common ancestor

    // THREE-LAYER FORK DETECTION (Professional fix)
    // Layer 1: Proactive O(1) chain mismatch (handled inline in DownloadBlocks)
    // Layer 2: Orphan block counter - consecutive orphans suggest fork
    std::atomic<int> m_consecutive_orphan_blocks{0};
    static constexpr int ORPHAN_FORK_THRESHOLD = 5;   // A3: Trigger fork check after 5 consecutive orphans (was 10)
    // B3: Block-flow timestamp for flow-aware Layer 3 gating
    // Uses atomic<int64_t> (steady_clock ticks) to avoid data race between
    // block-processing threads (write) and IBD thread (read).
    std::atomic<int64_t> m_last_block_connected_ticks;
    // Layer 3: Deep fork handling - requires manual reindex for security
    bool m_requires_reindex{false};
    static constexpr int MAX_AUTO_REORG_DEPTH = 100;  // Max blocks to auto-reorg

    // Resync tracking for completion message
    bool m_resync_in_progress{false};
    int m_resync_fork_point{0};
    int m_resync_original_height{0};
    int m_resync_target_height{0};

    // Fork detection frequency control (reduce CPU overhead)
    // PERFORMANCE FIX: Increased thresholds to prevent triggering during normal validation lag
    // Normal IBD has 2-10 second validation lag - don't misinterpret as fork
    int m_last_checked_chain_height{-1};      // Last chain height when fork detection ran
    static constexpr int FORK_DETECTION_THRESHOLD = 60;  // Cycles before triggering fork detection (was 5)
    std::chrono::steady_clock::time_point m_last_fork_check;  // Issue #6: Throttle fork checks
    static constexpr int FORK_CHECK_MIN_INTERVAL_SECS = 30;   // Min seconds between fork checks (was 5)

    // Issue #11 FIX: Request tracking as member variables (not static)
    int m_last_request_trigger{-1};
    bool m_initial_request_done{false};

    // Issue #7 FIX: Orphan scan frequency control
    std::chrono::steady_clock::time_point m_last_orphan_scan;
    static constexpr int ORPHAN_SCAN_INTERVAL_SECS = 30;      // Scan orphans every 30 seconds (was 10)

    // BUG #261 FIX: Startup grace period for fork detection
    // Skip fork detection during first N seconds after creation to allow:
    // - Header population from local blockchain to complete
    // - Peer connections to stabilize
    // - Headers chain to be fully indexed
    std::chrono::steady_clock::time_point m_creation_time;
    static constexpr int STARTUP_GRACE_PERIOD_SECS = 60;      // Skip fork detection for 60 seconds on startup
};

#endif // DILITHION_NODE_IBD_COORDINATOR_H

