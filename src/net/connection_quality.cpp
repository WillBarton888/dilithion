// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Connection Quality Metrics Implementation
 */

#include <net/connection_quality.h>
#include <algorithm>
#include <cmath>

void CConnectionQualityTracker::RecordBytesSent(int peer_id, size_t bytes) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_qualities[peer_id].bytes_sent += bytes;
    m_qualities[peer_id].last_message_time = std::chrono::steady_clock::now();
}

void CConnectionQualityTracker::RecordBytesReceived(int peer_id, size_t bytes) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_qualities[peer_id].bytes_received += bytes;
    m_qualities[peer_id].last_message_time = std::chrono::steady_clock::now();
}

void CConnectionQualityTracker::RecordMessageSent(int peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_qualities[peer_id].messages_sent++;
    m_qualities[peer_id].last_message_time = std::chrono::steady_clock::now();
}

void CConnectionQualityTracker::RecordMessageReceived(int peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_qualities[peer_id].messages_received++;
    m_qualities[peer_id].last_message_time = std::chrono::steady_clock::now();
}

void CConnectionQualityTracker::RecordError(int peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_qualities[peer_id].errors++;
    m_qualities[peer_id].consecutive_failures++;
}

void CConnectionQualityTracker::RecordLatency(int peer_id, double latency_ms) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& quality = m_qualities[peer_id];
    // Exponential moving average
    if (quality.latency_ms == 0.0) {
        quality.latency_ms = latency_ms;
    } else {
        quality.latency_ms = 0.7 * quality.latency_ms + 0.3 * latency_ms;
    }
}

ConnectionQuality CConnectionQualityTracker::GetQuality(int peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_qualities.find(peer_id);
    if (it == m_qualities.end()) {
        return ConnectionQuality();
    }
    return it->second;
}

double CConnectionQualityTracker::GetQualityScore(int peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_qualities.find(peer_id);
    if (it == m_qualities.end()) {
        return 0.0;
    }
    
    const auto& quality = it->second;
    
    // Calculate score based on multiple factors
    double score = 1.0;
    
    // Penalize errors (exponential decay)
    if (quality.errors > 0) {
        double error_penalty = 1.0 / (1.0 + quality.errors * 0.1);
        score *= error_penalty;
    }
    
    // Penalize consecutive failures
    if (quality.consecutive_failures > 0) {
        double failure_penalty = 1.0 / (1.0 + quality.consecutive_failures * 0.2);
        score *= failure_penalty;
    }
    
    // Penalize high latency (if > 1000ms, reduce score)
    if (quality.latency_ms > 1000.0) {
        double latency_penalty = 1000.0 / quality.latency_ms;
        score *= latency_penalty;
    }
    
    // Check if connection is stale (no messages in 5 minutes)
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
        now - quality.last_message_time).count();
    if (time_since_last > 300) {  // 5 minutes
        score *= 0.5;  // Reduce score for stale connections
    }
    
    return std::max(0.0, std::min(1.0, score));
}

void CConnectionQualityTracker::RemovePeer(int peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_qualities.erase(peer_id);
}

std::vector<int> CConnectionQualityTracker::GetTrackedPeers() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<int> peers;
    for (const auto& pair : m_qualities) {
        peers.push_back(pair.first);
    }
    return peers;
}

bool CConnectionQualityTracker::ShouldDisconnect(int peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_qualities.find(peer_id);
    if (it == m_qualities.end()) {
        return false;
    }
    
    const auto& quality = it->second;
    
    // Disconnect if too many consecutive failures
    if (quality.consecutive_failures >= MAX_CONSECUTIVE_FAILURES) {
        return true;
    }
    
    // Disconnect if quality score is too low
    double score = GetQualityScore(peer_id);
    if (score < MIN_QUALITY_SCORE) {
        return true;
    }
    
    return false;
}

