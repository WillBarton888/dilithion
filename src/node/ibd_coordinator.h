// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_IBD_COORDINATOR_H
#define DILITHION_NODE_IBD_COORDINATOR_H

#include <atomic>
#include <chrono>
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

    // Headers sync peer tracking (Bitcoin Core style single-sync-peer)
    int m_headers_sync_peer{-1};                                    // NodeId of current sync peer (-1 = none)
    std::chrono::steady_clock::time_point m_headers_sync_timeout;   // When to consider sync peer stalled
    int m_headers_sync_last_height{0};                              // Header height at last progress check
    bool m_headers_in_flight{false};                                // True while awaiting headers from sync peer
    static constexpr int HEADERS_SYNC_TIMEOUT_BASE_SECS = 45;       // 45 sec base timeout (faster failover)
    static constexpr int HEADERS_SYNC_TIMEOUT_PER_HEADER_MS = 1;    // +1ms per missing header

    // Blocks sync peer tracking (single peer for block download, different from headers peer)
    int m_blocks_sync_peer{-1};                                     // NodeId of block sync peer (-1 = none)

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
};

#endif // DILITHION_NODE_IBD_COORDINATOR_H

