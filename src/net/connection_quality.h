// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Connection Quality Metrics
 * Phase: Network Resilience
 * 
 * Tracks connection quality metrics for peer connections
 */

#ifndef DILITHION_NET_CONNECTION_QUALITY_H
#define DILITHION_NET_CONNECTION_QUALITY_H

#include <cstdint>
#include <chrono>
#include <map>
#include <mutex>
#include <string>

/**
 * Connection quality metrics for a peer
 */
struct ConnectionQuality {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t errors;
    std::chrono::steady_clock::time_point connected_time;
    std::chrono::steady_clock::time_point last_message_time;
    double latency_ms;  // Average latency in milliseconds
    uint32_t consecutive_failures;
    
    ConnectionQuality() 
        : bytes_sent(0), bytes_received(0), messages_sent(0), messages_received(0),
          errors(0), latency_ms(0.0), consecutive_failures(0) {
        connected_time = std::chrono::steady_clock::now();
        last_message_time = connected_time;
    }
};

/**
 * Connection quality tracker
 */
class CConnectionQualityTracker {
public:
    /**
     * Record bytes sent
     */
    void RecordBytesSent(int peer_id, size_t bytes);
    
    /**
     * Record bytes received
     */
    void RecordBytesReceived(int peer_id, size_t bytes);
    
    /**
     * Record message sent
     */
    void RecordMessageSent(int peer_id);
    
    /**
     * Record message received
     */
    void RecordMessageReceived(int peer_id);
    
    /**
     * Record error
     */
    void RecordError(int peer_id);
    
    /**
     * Record latency measurement
     */
    void RecordLatency(int peer_id, double latency_ms);
    
    /**
     * Get connection quality for a peer
     */
    ConnectionQuality GetQuality(int peer_id) const;
    
    /**
     * Get quality score (0.0 to 1.0, higher is better)
     */
    double GetQualityScore(int peer_id) const;
    
    /**
     * Remove peer from tracking
     */
    void RemovePeer(int peer_id);
    
    /**
     * Get all peer IDs being tracked
     */
    std::vector<int> GetTrackedPeers() const;
    
    /**
     * Check if peer should be disconnected due to poor quality
     */
    bool ShouldDisconnect(int peer_id) const;

private:
    mutable std::mutex m_mutex;
    std::map<int, ConnectionQuality> m_qualities;
    
    static constexpr uint32_t MAX_CONSECUTIVE_FAILURES = 10;
    static constexpr double MIN_QUALITY_SCORE = 0.1;  // Disconnect if score < 0.1
};

#endif // DILITHION_NET_CONNECTION_QUALITY_H

