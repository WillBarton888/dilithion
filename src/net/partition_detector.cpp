// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Network Partition Detection Implementation
 */

#include <net/partition_detector.h>
#include <algorithm>

CPartitionDetector::CPartitionDetector()
    : m_total_connections(0), m_failed_connections(0), m_successful_messages(0),
      m_consecutive_failures(0), m_is_partitioned(false) {
    m_last_successful_message = std::chrono::steady_clock::now();
}

void CPartitionDetector::RecordConnection() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_total_connections++;
    m_consecutive_failures = 0;  // Reset on successful connection
    m_is_partitioned = false;
}

void CPartitionDetector::RecordConnectionFailure() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_failed_connections++;
    m_consecutive_failures++;
    
    // Check if we've exceeded threshold
    if (m_consecutive_failures >= MAX_CONSECUTIVE_FAILURES) {
        m_is_partitioned = true;
    }
}

void CPartitionDetector::RecordMessageExchange() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_successful_messages++;
    m_consecutive_failures = 0;
    m_last_successful_message = std::chrono::steady_clock::now();
    m_is_partitioned = false;
}

bool CPartitionDetector::IsPartitioned() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check consecutive failures
    if (m_consecutive_failures >= MAX_CONSECUTIVE_FAILURES) {
        return true;
    }
    
    // Check if we haven't received messages in a while
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::minutes>(
        now - m_last_successful_message).count();
    
    if (time_since_last >= PARTITION_TIMEOUT.count() && m_total_connections > 0) {
        return true;
    }
    
    return m_is_partitioned;
}

double CPartitionDetector::GetPartitionSeverity() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_total_connections == 0) {
        return 1.0;  // No connections = fully partitioned
    }
    
    // Calculate severity based on failure rate
    double failure_rate = static_cast<double>(m_failed_connections) / 
                         static_cast<double>(m_total_connections + m_failed_connections);
    
    // Factor in consecutive failures
    double consecutive_penalty = std::min(1.0, static_cast<double>(m_consecutive_failures) / 
                                          static_cast<double>(MAX_CONSECUTIVE_FAILURES));
    
    // Factor in time since last message
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::minutes>(
        now - m_last_successful_message).count();
    double time_penalty = std::min(1.0, static_cast<double>(time_since_last) / 
                                  static_cast<double>(PARTITION_TIMEOUT.count()));
    
    // Combine factors
    double severity = (failure_rate * 0.4) + (consecutive_penalty * 0.3) + (time_penalty * 0.3);
    return std::min(1.0, severity);
}

void CPartitionDetector::Reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_consecutive_failures = 0;
    m_is_partitioned = false;
    m_last_successful_message = std::chrono::steady_clock::now();
}

CPartitionDetector::Stats CPartitionDetector::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    Stats stats;
    stats.total_connections = m_total_connections;
    stats.failed_connections = m_failed_connections;
    stats.successful_messages = m_successful_messages;
    stats.consecutive_failures = m_consecutive_failures;
    stats.is_partitioned = IsPartitioned();
    return stats;
}

