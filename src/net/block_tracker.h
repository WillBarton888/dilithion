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
#include <iostream>
#include <sstream>

/**
 * @file block_tracker.h
 * @brief SINGLE SOURCE OF TRUTH for per-block download tracking
 *
 * CBlockTracker tracks all in-flight block requests. No window - tracks exactly
 * what's requested. When a block arrives (by hash), lookup the height and clean up.
 *
 * Design:
 * - AddBlock(height, hash, peer) - called when requesting a block
 * - OnBlockReceived(hash) - called when block arrives, O(1) cleanup via hash lookup
 * - GetPeerInFlightCount(peer) - for capacity limits
 * - OnPeerDisconnected(peer) - cleanup when peer goes away
 */

using NodeId = int;

/**
 * @brief Block state (simplified - just tracking in-flight)
 */
enum class BlockState {
    IN_FLIGHT,    ///< Requested from peer, awaiting response
    RECEIVED      ///< Block received (will be removed from tracking shortly)
};

/**
 * @class CBlockTracker
 * @brief Single source of truth for block download state
 *
 * Thread-safe: All public methods acquire the internal mutex.
 */
class CBlockTracker {
public:
    // Configuration
    static constexpr int MAX_PER_PEER = 128;           ///< Maximum in-flight blocks per peer
    static constexpr int MAX_TOTAL = 256;              ///< Maximum total in-flight blocks
    static constexpr int TIMEOUT_SECONDS = 120;        ///< Seconds before block times out

    CBlockTracker() = default;

    // =========================================================================
    // Core Operations
    // =========================================================================

    /**
     * @brief Add a block to tracking when requesting from peer
     * @param height Block height
     * @param hash Block hash
     * @param peer Peer we're requesting from
     * @return true if added, false if already tracked or at capacity
     */
    bool AddBlock(int height, const uint256& hash, NodeId peer) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Already tracking this height?
        if (m_heights.count(height) > 0) {
            return false;
        }

        // Check capacity
        if (GetPeerInFlightCountLocked(peer) >= MAX_PER_PEER) {
            return false;
        }
        if (GetTotalInFlightLocked() >= MAX_TOTAL) {
            return false;
        }

        // Add to tracking
        m_heights[height] = BlockInfo{
            hash,
            peer,
            std::chrono::steady_clock::now()
        };

        // Update indexes
        m_hash_to_height[hash] = height;
        m_peer_heights[peer].insert(height);

        return true;
    }

    /**
     * @brief Called when block arrives - looks up height from hash and cleans up
     * @param hash Block hash
     * @return height if found and cleaned up, -1 if not tracked
     */
    int OnBlockReceived(const uint256& hash) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Lookup height from hash
        auto hash_it = m_hash_to_height.find(hash);
        if (hash_it == m_hash_to_height.end()) {
            return -1;  // Not tracked
        }

        int height = hash_it->second;

        // Get the block info
        auto height_it = m_heights.find(height);
        if (height_it == m_heights.end()) {
            // Inconsistent state - clean up hash map
            m_hash_to_height.erase(hash_it);
            return -1;
        }

        NodeId peer = height_it->second.peer;

        // Clean up peer tracking
        auto peer_it = m_peer_heights.find(peer);
        if (peer_it != m_peer_heights.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                m_peer_heights.erase(peer_it);
            }
        }

        // Clean up hash and height maps
        m_hash_to_height.erase(hash_it);
        m_heights.erase(height_it);

        return height;
    }

    /**
     * @brief Called when block arrives (by height if known)
     * @param height Block height
     * @return true if found and cleaned up
     */
    bool OnBlockReceivedByHeight(int height) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto height_it = m_heights.find(height);
        if (height_it == m_heights.end()) {
            return false;  // Not tracked
        }

        uint256 hash = height_it->second.hash;
        NodeId peer = height_it->second.peer;

        // Clean up peer tracking
        auto peer_it = m_peer_heights.find(peer);
        if (peer_it != m_peer_heights.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                m_peer_heights.erase(peer_it);
            }
        }

        // Clean up hash and height maps
        m_hash_to_height.erase(hash);
        m_heights.erase(height_it);

        return true;
    }

    /**
     * @brief Handle peer disconnection - remove all peer's blocks from tracking
     * @param peer Disconnected peer ID
     * @return Vector of heights that were being downloaded from this peer
     */
    std::vector<int> OnPeerDisconnected(NodeId peer) {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<int> heights_returned;

        auto peer_it = m_peer_heights.find(peer);
        if (peer_it == m_peer_heights.end()) {
            return heights_returned;
        }

        // Copy the set since we'll modify m_heights
        std::set<int> heights = peer_it->second;

        for (int height : heights) {
            auto h_it = m_heights.find(height);
            if (h_it != m_heights.end()) {
                // Remove from hash map
                m_hash_to_height.erase(h_it->second.hash);
                // Remove from heights
                m_heights.erase(h_it);
                heights_returned.push_back(height);
            }
        }

        m_peer_heights.erase(peer_it);

        return heights_returned;
    }

    // =========================================================================
    // Queries
    // =========================================================================

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
     * @brief Get total number of in-flight blocks
     */
    int GetTotalInFlight() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_heights.size();
    }

    /**
     * @brief Check if a height is being tracked
     */
    bool IsTracked(int height) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_heights.count(height) > 0;
    }

    /**
     * @brief Get height for a hash (for external callers)
     */
    int GetHeightForHash(const uint256& hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hash_to_height.find(hash);
        return (it != m_hash_to_height.end()) ? it->second : -1;
    }

    /**
     * @brief Get heights that have timed out
     * @param timeout_seconds Custom timeout (default: TIMEOUT_SECONDS)
     */
    std::vector<std::pair<int, NodeId>> CheckTimeouts(int timeout_seconds = TIMEOUT_SECONDS) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<std::pair<int, NodeId>> timed_out;
        auto now = std::chrono::steady_clock::now();
        auto timeout = std::chrono::seconds(timeout_seconds);

        for (const auto& [height, info] : m_heights) {
            if (now - info.request_time > timeout) {
                timed_out.push_back({height, info.peer});
            }
        }

        return timed_out;
    }

    /**
     * @brief Remove a timed-out block from tracking
     * @return The peer that was downloading it
     */
    NodeId RemoveTimedOut(int height) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto height_it = m_heights.find(height);
        if (height_it == m_heights.end()) {
            return -1;
        }

        NodeId peer = height_it->second.peer;
        uint256 hash = height_it->second.hash;

        // Clean up peer tracking
        auto peer_it = m_peer_heights.find(peer);
        if (peer_it != m_peer_heights.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                m_peer_heights.erase(peer_it);
            }
        }

        // Clean up maps
        m_hash_to_height.erase(hash);
        m_heights.erase(height_it);

        return peer;
    }

    /**
     * @brief Get status string for logging
     */
    std::string GetStatus() const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::ostringstream ss;
        ss << "InFlight=" << m_heights.size()
           << " peers=" << m_peer_heights.size();
        return ss.str();
    }

    /**
     * @brief Check if tracker has any blocks
     */
    bool IsInitialized() const {
        // For compatibility - always return true so callers use us
        return true;
    }

    /**
     * @brief Clear all tracking (for reset/reinit)
     */
    void Clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_heights.clear();
        m_hash_to_height.clear();
        m_peer_heights.clear();
    }

private:
    mutable std::mutex m_mutex;

    // Per-height state
    struct BlockInfo {
        uint256 hash;
        NodeId peer;
        std::chrono::steady_clock::time_point request_time;
    };
    std::map<int, BlockInfo> m_heights;              ///< height -> info

    // Indexes for O(1) lookups
    std::map<uint256, int> m_hash_to_height;         ///< hash -> height
    std::map<NodeId, std::set<int>> m_peer_heights;  ///< peer -> set of heights

    // =========================================================================
    // Internal helpers (must be called with lock held)
    // =========================================================================

    int GetPeerInFlightCountLocked(NodeId peer) const {
        auto it = m_peer_heights.find(peer);
        return (it != m_peer_heights.end()) ? it->second.size() : 0;
    }

    int GetTotalInFlightLocked() const {
        return m_heights.size();
    }
};

#endif // DILITHION_BLOCK_TRACKER_H
