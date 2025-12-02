// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Bandwidth Throttling
 * Phase: Network Resilience
 * 
 * Implements rate limiting and bandwidth throttling for P2P connections
 */

#ifndef DILITHION_NET_BANDWIDTH_THROTTLE_H
#define DILITHION_NET_BANDWIDTH_THROTTLE_H

#include <cstdint>
#include <chrono>
#include <map>
#include <mutex>

/**
 * Bandwidth throttler for P2P connections
 * 
 * Implements token bucket algorithm for rate limiting
 */
class CBandwidthThrottle {
public:
    /**
     * Constructor
     * @param max_bytes_per_second Maximum bytes per second (0 = unlimited)
     */
    explicit CBandwidthThrottle(uint64_t max_bytes_per_second = 0);
    
    /**
     * Check if we can send data (non-blocking)
     * @param bytes Number of bytes to send
     * @return true if allowed, false if throttled
     */
    bool CanSend(size_t bytes);
    
    /**
     * Record bytes sent (updates token bucket)
     * @param bytes Number of bytes sent
     */
    void RecordSent(size_t bytes);
    
    /**
     * Get current available bandwidth (bytes per second)
     */
    uint64_t GetAvailableBandwidth() const;
    
    /**
     * Set maximum bandwidth (bytes per second, 0 = unlimited)
     */
    void SetMaxBandwidth(uint64_t max_bytes_per_second);
    
    /**
     * Reset throttle state
     */
    void Reset();

private:
    uint64_t m_max_bytes_per_second;
    uint64_t m_tokens;  // Current tokens in bucket
    std::chrono::steady_clock::time_point m_last_update;
    mutable std::mutex m_mutex;
    
    static constexpr uint64_t BUCKET_SIZE = 1024 * 1024;  // 1 MB bucket
    static constexpr uint64_t REFILL_INTERVAL_MS = 100;   // Refill every 100ms
};

/**
 * Per-peer bandwidth throttling
 */
class CPerPeerThrottle {
public:
    /**
     * Check if peer can send/receive data
     * @param peer_id Peer ID
     * @param bytes Number of bytes
     * @param is_send true for send, false for receive
     * @return true if allowed
     */
    bool CanTransfer(int peer_id, size_t bytes, bool is_send);
    
    /**
     * Record bytes transferred
     * @param peer_id Peer ID
     * @param bytes Number of bytes
     * @param is_send true for send, false for receive
     */
    void RecordTransfer(int peer_id, size_t bytes, bool is_send);
    
    /**
     * Remove peer from throttling
     * @param peer_id Peer ID
     */
    void RemovePeer(int peer_id);

private:
    std::map<int, CBandwidthThrottle> m_send_throttles;
    std::map<int, CBandwidthThrottle> m_recv_throttles;
    mutable std::mutex m_mutex;
    
    static constexpr uint64_t DEFAULT_PEER_BANDWIDTH = 2 * 1024 * 1024;  // 2 MB/s per peer
};

#endif // DILITHION_NET_BANDWIDTH_THROTTLE_H

