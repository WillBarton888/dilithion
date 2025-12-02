// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Bandwidth Throttling Implementation
 */

#include <net/bandwidth_throttle.h>
#include <algorithm>
#include <chrono>

CBandwidthThrottle::CBandwidthThrottle(uint64_t max_bytes_per_second)
    : m_max_bytes_per_second(max_bytes_per_second),
      m_tokens(BUCKET_SIZE),
      m_last_update(std::chrono::steady_clock::now()) {
}

bool CBandwidthThrottle::CanSend(size_t bytes) {
    if (m_max_bytes_per_second == 0) {
        return true;  // Unlimited
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Refill tokens based on elapsed time
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_last_update).count();
    
    if (elapsed >= REFILL_INTERVAL_MS) {
        uint64_t tokens_to_add = (m_max_bytes_per_second * elapsed) / 1000;
        m_tokens = std::min(BUCKET_SIZE, m_tokens + tokens_to_add);
        m_last_update = now;
    }
    
    return bytes <= m_tokens;
}

void CBandwidthThrottle::RecordSent(size_t bytes) {
    if (m_max_bytes_per_second == 0) {
        return;  // Unlimited
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Refill tokens
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_last_update).count();
    
    if (elapsed >= REFILL_INTERVAL_MS) {
        uint64_t tokens_to_add = (m_max_bytes_per_second * elapsed) / 1000;
        m_tokens = std::min(BUCKET_SIZE, m_tokens + tokens_to_add);
        m_last_update = now;
    }
    
    // Consume tokens
    if (bytes <= m_tokens) {
        m_tokens -= bytes;
    } else {
        m_tokens = 0;  // Over limit, but allow it
    }
}

uint64_t CBandwidthThrottle::GetAvailableBandwidth() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tokens;
}

void CBandwidthThrottle::SetMaxBandwidth(uint64_t max_bytes_per_second) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_max_bytes_per_second = max_bytes_per_second;
    m_tokens = BUCKET_SIZE;  // Reset bucket
}

void CBandwidthThrottle::Reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tokens = BUCKET_SIZE;
    m_last_update = std::chrono::steady_clock::now();
}

bool CPerPeerThrottle::CanTransfer(int peer_id, size_t bytes, bool is_send) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (is_send) {
        auto it = m_send_throttles.find(peer_id);
        if (it == m_send_throttles.end()) {
            // Create throttle for new peer
            m_send_throttles.emplace(peer_id, CBandwidthThrottle(DEFAULT_PEER_BANDWIDTH));
            return true;  // Allow first transfer
        }
        return it->second.CanSend(bytes);
    } else {
        auto it = m_recv_throttles.find(peer_id);
        if (it == m_recv_throttles.end()) {
            m_recv_throttles.emplace(peer_id, CBandwidthThrottle(DEFAULT_PEER_BANDWIDTH));
            return true;
        }
        return it->second.CanSend(bytes);
    }
}

void CPerPeerThrottle::RecordTransfer(int peer_id, size_t bytes, bool is_send) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (is_send) {
        auto it = m_send_throttles.find(peer_id);
        if (it != m_send_throttles.end()) {
            it->second.RecordSent(bytes);
        }
    } else {
        auto it = m_recv_throttles.find(peer_id);
        if (it != m_recv_throttles.end()) {
            it->second.RecordSent(bytes);
        }
    }
}

void CPerPeerThrottle::RemovePeer(int peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_send_throttles.erase(peer_id);
    m_recv_throttles.erase(peer_id);
}

