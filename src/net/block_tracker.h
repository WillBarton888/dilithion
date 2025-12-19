// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_BLOCK_TRACKER_H
#define DILITHION_BLOCK_TRACKER_H

#include <uint256.h>
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <chrono>
#include <functional>
#include <iostream>
#include <sstream>

/**
 * @file block_tracker.h
 * @brief Unified block download state tracking for IBD
 *
 * CBlockTracker is the SINGLE SOURCE OF TRUTH for all block download state.
 * It replaces the fragmented tracking across CBlockDownloadWindow, chunk tracking,
 * and CPeerManager that caused race conditions and state desync.
 *
 * Design principles:
 * 1. ONE state per height - no ambiguity
 * 2. ONE mutex - no race conditions
 * 3. Derived indexes maintained atomically
 * 4. Idempotent operations - safe to call multiple times
 */

using NodeId = int;

/**
 * @brief Block download state machine
 *
 * Each height transitions through these states:
 *   KNOWN -> PENDING -> IN_FLIGHT -> RECEIVED -> CONNECTED
 *                 ^         |
 *                 +--timeout-+
 */
enum class BlockState {
    UNKNOWN,      ///< Not yet discovered (no header)
    KNOWN,        ///< Header received, hash known, not yet in window
    PENDING,      ///< In window, waiting for peer assignment
    IN_FLIGHT,    ///< Requested from peer, awaiting response
    RECEIVED,     ///< Block data received, awaiting validation
    CONNECTED     ///< Block connected to active chain
};

inline const char* BlockStateToString(BlockState state) {
    switch (state) {
        case BlockState::UNKNOWN: return "UNKNOWN";
        case BlockState::KNOWN: return "KNOWN";
        case BlockState::PENDING: return "PENDING";
        case BlockState::IN_FLIGHT: return "IN_FLIGHT";
        case BlockState::RECEIVED: return "RECEIVED";
        case BlockState::CONNECTED: return "CONNECTED";
        default: return "INVALID";
    }
}

/**
 * @class CBlockTracker
 * @brief Single source of truth for block download state
 *
 * Thread-safe: All public methods acquire the internal mutex.
 * All state transitions are atomic and idempotent.
 */
class CBlockTracker {
public:
    // Configuration constants
    static constexpr int WINDOW_SIZE = 1024;           ///< Maximum blocks in active window
    static constexpr int MAX_PER_PEER = 64;            ///< Maximum in-flight blocks per peer
    static constexpr int TIMEOUT_SECONDS = 120;        ///< Seconds before IN_FLIGHT times out
    static constexpr int MAX_RETRIES = 3;              ///< Max retries before giving up on height

    CBlockTracker() : m_window_start(1), m_target_height(0), m_connected_height(0) {}

    // =========================================================================
    // Initialization
    // =========================================================================

    /**
     * @brief Initialize tracker for IBD
     * @param connected_height Current chain height (highest connected block)
     * @param target_height Target height to sync to (header height)
     */
    void Initialize(int connected_height, int target_height) {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_connected_height = connected_height;
        m_target_height = target_height;
        m_window_start = connected_height + 1;

        // Clear any existing state
        m_heights.clear();
        m_pending.clear();
        m_peer_heights.clear();
        m_received.clear();

        // Populate initial window with PENDING heights
        int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
        for (int h = m_window_start; h <= window_end; h++) {
            m_heights[h] = HeightState{
                BlockState::PENDING,
                uint256(),  // Hash will be set by caller
                -1,         // No peer assigned
                {},         // No request time
                0           // No retries
            };
            m_pending.insert(h);
        }

        std::cout << "[BlockTracker] Initialized: window=[" << m_window_start
                  << "-" << window_end << "] target=" << m_target_height
                  << " pending=" << m_pending.size() << std::endl;
    }

    /**
     * @brief Set hash for a height (from headers)
     * @param height Block height
     * @param hash Block hash
     */
    void SetHash(int height, const uint256& hash) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_heights.find(height);
        if (it != m_heights.end()) {
            it->second.hash = hash;
        }
    }

    // =========================================================================
    // State Transitions
    // =========================================================================

    /**
     * @brief Assign a PENDING height to a peer (PENDING -> IN_FLIGHT)
     * @param height Block height to assign
     * @param peer Peer to assign to
     * @return true if assignment succeeded, false if height not PENDING or peer at capacity
     */
    bool AssignToPeer(int height, NodeId peer) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_heights.find(height);
        if (it == m_heights.end()) {
            return false;  // Height not in window
        }

        if (it->second.state != BlockState::PENDING) {
            return false;  // Not in PENDING state
        }

        if (GetPeerInFlightCountLocked(peer) >= MAX_PER_PEER) {
            return false;  // Peer at capacity
        }

        // Atomic state transition
        it->second.state = BlockState::IN_FLIGHT;
        it->second.peer = peer;
        it->second.request_time = std::chrono::steady_clock::now();

        // Update derived indexes
        m_pending.erase(height);
        m_peer_heights[peer].insert(height);

        return true;
    }

    /**
     * @brief Mark block as received (IN_FLIGHT or PENDING -> RECEIVED)
     * @param height Block height
     * @param peer Peer that sent the block (optional, for logging)
     *
     * Idempotent: safe to call multiple times or for already-received blocks.
     */
    void OnBlockReceived(int height, NodeId peer = -1) {
        (void)peer;  // Used for future logging
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_heights.find(height);
        if (it == m_heights.end()) {
            // Height not in window - could be late arrival after window advanced
            return;
        }

        BlockState current = it->second.state;

        // Accept from IN_FLIGHT or PENDING (late arrival after timeout)
        if (current == BlockState::IN_FLIGHT || current == BlockState::PENDING) {
            // Clean up peer tracking if was assigned
            if (it->second.peer != -1) {
                auto peer_it = m_peer_heights.find(it->second.peer);
                if (peer_it != m_peer_heights.end()) {
                    peer_it->second.erase(height);
                    if (peer_it->second.empty()) {
                        m_peer_heights.erase(peer_it);
                    }
                }
            }

            // Transition to RECEIVED
            it->second.state = BlockState::RECEIVED;
            it->second.peer = -1;
            m_pending.erase(height);
            m_received.insert(height);
        }
        // If already RECEIVED or CONNECTED, ignore (idempotent)
    }

    /**
     * @brief Mark block as connected to chain (RECEIVED -> CONNECTED)
     * @param height Block height
     *
     * Also advances the window if this was the lowest pending height.
     */
    void OnBlockConnected(int height) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_heights.find(height);
        if (it == m_heights.end()) {
            // Height not tracked - might be before window start
            if (height > m_connected_height) {
                m_connected_height = height;
            }
            return;
        }

        if (it->second.state == BlockState::RECEIVED) {
            it->second.state = BlockState::CONNECTED;
            m_received.erase(height);
        }

        // Update connected height
        if (height > m_connected_height) {
            m_connected_height = height;
        }

        // Try to advance window
        AdvanceWindowLocked();
    }

    /**
     * @brief Handle timeout (IN_FLIGHT -> PENDING)
     * @param height Block height that timed out
     */
    void OnTimeout(int height) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_heights.find(height);
        if (it == m_heights.end() || it->second.state != BlockState::IN_FLIGHT) {
            return;  // Not in IN_FLIGHT state
        }

        NodeId old_peer = it->second.peer;

        // Clean up peer tracking
        if (old_peer != -1) {
            auto peer_it = m_peer_heights.find(old_peer);
            if (peer_it != m_peer_heights.end()) {
                peer_it->second.erase(height);
                if (peer_it->second.empty()) {
                    m_peer_heights.erase(peer_it);
                }
            }
        }

        // Transition back to PENDING
        it->second.state = BlockState::PENDING;
        it->second.peer = -1;
        it->second.retry_count++;
        m_pending.insert(height);

        std::cout << "[BlockTracker] Height " << height << " timed out from peer "
                  << old_peer << " (retry " << it->second.retry_count << ")" << std::endl;
    }

    /**
     * @brief Handle peer disconnection - return all peer's heights to PENDING
     * @param peer Disconnected peer ID
     */
    void OnPeerDisconnected(NodeId peer) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto peer_it = m_peer_heights.find(peer);
        if (peer_it == m_peer_heights.end()) {
            return;  // Peer had no in-flight blocks
        }

        // Copy the set since we'll modify m_heights
        std::set<int> heights = peer_it->second;

        for (int height : heights) {
            auto h_it = m_heights.find(height);
            if (h_it != m_heights.end() && h_it->second.state == BlockState::IN_FLIGHT) {
                h_it->second.state = BlockState::PENDING;
                h_it->second.peer = -1;
                m_pending.insert(height);
            }
        }

        m_peer_heights.erase(peer_it);

        std::cout << "[BlockTracker] Peer " << peer << " disconnected, returned "
                  << heights.size() << " heights to pending" << std::endl;
    }

    // =========================================================================
    // Queries
    // =========================================================================

    /**
     * @brief Get state of a height
     */
    BlockState GetState(int height) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (height <= m_connected_height) {
            return BlockState::CONNECTED;
        }

        auto it = m_heights.find(height);
        if (it != m_heights.end()) {
            return it->second.state;
        }

        if (height > m_target_height) {
            return BlockState::UNKNOWN;
        }

        return BlockState::KNOWN;  // Beyond window but has header
    }

    /**
     * @brief Get pending heights for assignment
     * @param max_count Maximum heights to return
     * @return Vector of heights in PENDING state, sorted ascending
     */
    std::vector<int> GetPendingHeights(int max_count) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<int> result;
        result.reserve(std::min(max_count, (int)m_pending.size()));

        for (int h : m_pending) {
            if ((int)result.size() >= max_count) break;
            result.push_back(h);
        }

        return result;
    }

    /**
     * @brief Get number of in-flight blocks for a peer
     */
    int GetPeerInFlightCount(NodeId peer) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return GetPeerInFlightCountLocked(peer);
    }

    /**
     * @brief Check if peer has capacity for more blocks
     */
    bool HasPeerCapacity(NodeId peer) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return GetPeerInFlightCountLocked(peer) < MAX_PER_PEER;
    }

    /**
     * @brief Get heights that have timed out
     * @return Vector of heights in IN_FLIGHT state past timeout
     */
    std::vector<int> CheckTimeouts() const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<int> timed_out;
        auto now = std::chrono::steady_clock::now();
        auto timeout = std::chrono::seconds(TIMEOUT_SECONDS);

        for (const auto& [height, state] : m_heights) {
            if (state.state == BlockState::IN_FLIGHT) {
                if (now - state.request_time > timeout) {
                    timed_out.push_back(height);
                }
            }
        }

        return timed_out;
    }

    /**
     * @brief Get hash for a height
     */
    uint256 GetHash(int height) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_heights.find(height);
        if (it != m_heights.end()) {
            return it->second.hash;
        }
        return uint256();
    }

    // =========================================================================
    // Window Management
    // =========================================================================

    /**
     * @brief Update target height (when new headers arrive)
     * @param new_target New target height
     */
    void UpdateTarget(int new_target) {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (new_target <= m_target_height) {
            return;  // Target unchanged or decreased
        }

        int old_target = m_target_height;
        m_target_height = new_target;

        // Add new heights to window if space available
        int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
        for (int h = old_target + 1; h <= window_end; h++) {
            if (m_heights.find(h) == m_heights.end()) {
                m_heights[h] = HeightState{
                    BlockState::PENDING,
                    uint256(),
                    -1,
                    {},
                    0
                };
                m_pending.insert(h);
            }
        }
    }

    /**
     * @brief Get status string for logging
     */
    std::string GetStatus() const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::ostringstream ss;
        ss << "Window [" << m_window_start << "-" << (m_window_start + WINDOW_SIZE - 1)
           << "/" << m_target_height << "] connected=" << m_connected_height
           << " pending=" << m_pending.size()
           << " in_flight=" << GetTotalInFlightLocked()
           << " received=" << m_received.size();
        return ss.str();
    }

    /**
     * @brief Check if tracker is initialized
     */
    bool IsInitialized() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_target_height > 0;
    }

    /**
     * @brief Get connected height
     */
    int GetConnectedHeight() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_connected_height;
    }

    /**
     * @brief Get window start
     */
    int GetWindowStart() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_window_start;
    }

    /**
     * @brief Get target height
     */
    int GetTargetHeight() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_target_height;
    }

    /**
     * @brief Get pending count
     */
    int GetPendingCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pending.size();
    }

    /**
     * @brief Check if IBD is complete
     */
    bool IsComplete() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_connected_height >= m_target_height && m_target_height > 0;
    }
private:
    mutable std::mutex m_mutex;

    // Core state
    int m_window_start;       ///< First height in active window
    int m_target_height;      ///< Target height (header height)
    int m_connected_height;   ///< Highest connected height

    // Per-height state
    struct HeightState {
        BlockState state;
        uint256 hash;
        NodeId peer;          ///< Assigned peer (-1 if not IN_FLIGHT)
        std::chrono::steady_clock::time_point request_time;
        int retry_count;
    };
    std::map<int, HeightState> m_heights;

    // Derived indexes (maintained atomically with m_heights)
    std::set<int> m_pending;                       ///< Heights in PENDING state
    std::map<NodeId, std::set<int>> m_peer_heights; ///< Peer -> IN_FLIGHT heights
    std::set<int> m_received;                      ///< Heights in RECEIVED state

    // =========================================================================
    // Internal helpers (must be called with lock held)
    // =========================================================================

    int GetPeerInFlightCountLocked(NodeId peer) const {
        auto it = m_peer_heights.find(peer);
        if (it != m_peer_heights.end()) {
            return it->second.size();
        }
        return 0;
    }

    int GetTotalInFlightLocked() const {
        int total = 0;
        for (const auto& [peer, heights] : m_peer_heights) {
            total += heights.size();
        }
        return total;
    }

    void AdvanceWindowLocked() {
        // Window can only advance when connected_height increases
        int new_start = m_connected_height + 1;

        if (new_start <= m_window_start) {
            return;  // Nothing to advance
        }

        // Remove heights that are now before window
        while (m_window_start < new_start) {
            auto it = m_heights.find(m_window_start);
            if (it != m_heights.end()) {
                // Clean up from derived indexes
                m_pending.erase(m_window_start);
                m_received.erase(m_window_start);
                if (it->second.peer != -1) {
                    auto peer_it = m_peer_heights.find(it->second.peer);
                    if (peer_it != m_peer_heights.end()) {
                        peer_it->second.erase(m_window_start);
                    }
                }
                m_heights.erase(it);
            }
            m_window_start++;
        }

        // Add new heights to fill window
        int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
        for (int h = m_window_start; h <= window_end; h++) {
            if (m_heights.find(h) == m_heights.end()) {
                m_heights[h] = HeightState{
                    BlockState::PENDING,
                    uint256(),
                    -1,
                    {},
                    0
                };
                m_pending.insert(h);
            }
        }
    }

#ifdef DEBUG
    void CheckInvariants() const {
        // Invariant 1: m_pending contains exactly heights in PENDING state
        for (int h : m_pending) {
            assert(m_heights.at(h).state == BlockState::PENDING);
        }
        for (const auto& [h, state] : m_heights) {
            if (state.state == BlockState::PENDING) {
                assert(m_pending.count(h) > 0);
            }
        }

        // Invariant 2: m_peer_heights contains exactly IN_FLIGHT heights
        for (const auto& [peer, heights] : m_peer_heights) {
            for (int h : heights) {
                assert(m_heights.at(h).state == BlockState::IN_FLIGHT);
                assert(m_heights.at(h).peer == peer);
            }
        }
        for (const auto& [h, state] : m_heights) {
            if (state.state == BlockState::IN_FLIGHT) {
                assert(m_peer_heights.count(state.peer) > 0);
                assert(m_peer_heights.at(state.peer).count(h) > 0);
            }
        }

        // Invariant 3: Per-peer count within limits
        for (const auto& [peer, heights] : m_peer_heights) {
            assert(heights.size() <= MAX_PER_PEER);
        }

        // Invariant 4: All heights in window range
        for (const auto& [h, state] : m_heights) {
            assert(h >= m_window_start);
            assert(h < m_window_start + WINDOW_SIZE || h <= m_target_height);
        }
    }
#endif
};

#endif // DILITHION_BLOCK_TRACKER_H
