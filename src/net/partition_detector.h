// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Network Partition Detection
 * Phase: Network Resilience
 * 
 * Detects network partitions and handles them gracefully
 */

#ifndef DILITHION_NET_PARTITION_DETECTOR_H
#define DILITHION_NET_PARTITION_DETECTOR_H

#include <cstdint>
#include <chrono>
#include <vector>
#include <mutex>

/**
 * Network partition detector
 * 
 * Detects when the node is isolated from the network
 */
class CPartitionDetector {
public:
    CPartitionDetector();
    
    /**
     * Record a successful connection
     */
    void RecordConnection();
    
    /**
     * Record a connection failure
     */
    void RecordConnectionFailure();
    
    /**
     * Record a successful message exchange
     */
    void RecordMessageExchange();
    
    /**
     * Check if we're in a network partition
     * @return true if partition detected
     */
    bool IsPartitioned() const;
    
    /**
     * Get partition severity (0.0 to 1.0, higher = more severe)
     */
    double GetPartitionSeverity() const;
    
    /**
     * Reset partition detection state
     */
    void Reset();
    
    /**
     * Get statistics
     */
    struct Stats {
        uint64_t total_connections;
        uint64_t failed_connections;
        uint64_t successful_messages;
        uint64_t consecutive_failures;
        bool is_partitioned;
    };
    Stats GetStats() const;

private:
    mutable std::mutex m_mutex;
    
    uint64_t m_total_connections;
    uint64_t m_failed_connections;
    uint64_t m_successful_messages;
    uint64_t m_consecutive_failures;
    std::chrono::steady_clock::time_point m_last_successful_message;
    bool m_is_partitioned;
    
    static constexpr uint64_t MAX_CONSECUTIVE_FAILURES = 20;
    static constexpr std::chrono::minutes PARTITION_TIMEOUT = std::chrono::minutes(10);
};

#endif // DILITHION_NET_PARTITION_DETECTOR_H

