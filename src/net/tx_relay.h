// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_TX_RELAY_H
#define DILITHION_NET_TX_RELAY_H

#include <uint256.h>
#include <node/mempool.h>
#include <map>
#include <set>
#include <chrono>
#include <mutex>

/**
 * CTxRelayManager
 *
 * Manages transaction relay state and flood prevention for the P2P network.
 *
 * This class tracks which transactions have been announced to which peers,
 * manages in-flight transaction requests, and prevents flooding/duplicate
 * announcements.
 *
 * Thread Safety: All methods are thread-safe via internal mutex.
 *
 * Flood Prevention:
 * - Tracks announced transactions with TTL (Time-To-Live)
 * - Prevents re-announcing same transaction to same peer
 * - Tracks in-flight requests with timeout
 * - Automatic cleanup of expired entries
 */
class CTxRelayManager {
private:
    mutable std::mutex cs;

    // Track which transactions we've announced to which peers
    // Maps NodeId -> set<txid>
    std::map<int64_t, std::set<uint256>> tx_inv_sent;

    // Track transactions we've requested (prevent duplicate requests)
    // Maps txid -> NodeId (the peer we requested from)
    std::map<uint256, int64_t> tx_in_flight;

    // Track when we requested each transaction (for timeout detection)
    std::map<uint256, std::chrono::steady_clock::time_point> tx_request_time;

    // Recently announced transactions (prevent flooding)
    // Maps txid -> announcement time
    std::map<uint256, std::chrono::steady_clock::time_point> recently_announced;

    // Configuration constants
    static const int TX_REQUEST_TIMEOUT = 60;  // seconds
    static const int TX_ANNOUNCE_TTL = 15;      // seconds

public:
    CTxRelayManager();
    ~CTxRelayManager();

    /**
     * ShouldAnnounce
     *
     * Check if we should announce this transaction to this peer.
     * Returns false if we've already announced it to this peer,
     * or if it was recently announced globally.
     *
     * @param peer_id The peer node ID
     * @param txid Transaction hash
     * @return true if we should announce, false if already announced
     */
    bool ShouldAnnounce(int64_t peer_id, const uint256& txid);

    /**
     * MarkAnnounced
     *
     * Mark that we've announced this transaction to this peer.
     * This prevents re-announcing the same transaction.
     *
     * @param peer_id The peer node ID
     * @param txid Transaction hash
     */
    void MarkAnnounced(int64_t peer_id, const uint256& txid);

    /**
     * AlreadyHave
     *
     * Check if we already have this transaction (in mempool)
     * or if we've already requested it from another peer.
     *
     * @param txid Transaction hash
     * @param mempool Reference to transaction mempool
     * @return true if we have it or already requested it
     */
    bool AlreadyHave(const uint256& txid, CTxMemPool& mempool);

    /**
     * MarkRequested
     *
     * Mark that we've requested this transaction from a peer.
     * This prevents duplicate requests and tracks the source.
     *
     * @param txid Transaction hash
     * @param peer_id The peer node ID we're requesting from
     */
    void MarkRequested(const uint256& txid, int64_t peer_id);

    /**
     * RemoveInFlight
     *
     * Remove transaction from in-flight tracking.
     * Called when transaction is received or request times out.
     *
     * @param txid Transaction hash
     */
    void RemoveInFlight(const uint256& txid);

    /**
     * CleanupExpired
     *
     * Clean up expired entries to prevent memory growth.
     * Should be called periodically (e.g., every 60 seconds).
     *
     * Removes:
     * - Timed-out in-flight requests (>TX_REQUEST_TIMEOUT seconds old)
     * - Expired recently_announced entries (>TX_ANNOUNCE_TTL seconds old)
     */
    void CleanupExpired();

    /**
     * PeerDisconnected
     *
     * Clear all state for a disconnected peer.
     * Removes tracking data to prevent memory leaks.
     *
     * @param peer_id The disconnected peer node ID
     */
    void PeerDisconnected(int64_t peer_id);

    /**
     * GetStats
     *
     * Get relay manager statistics for monitoring.
     *
     * @param announced_count Output: Number of peer->tx announcement mappings
     * @param in_flight_count Output: Number of in-flight requests
     * @param recent_count Output: Number of recently announced transactions
     */
    void GetStats(size_t& announced_count, size_t& in_flight_count, size_t& recent_count) const;
};

#endif // DILITHION_NET_TX_RELAY_H
