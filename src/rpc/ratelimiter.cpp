// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/ratelimiter.h>

// Configuration constants
const std::chrono::seconds CRateLimiter::WINDOW_DURATION(60);  // 1 minute
const std::chrono::seconds CRateLimiter::AUTH_LOCKOUT_DURATION(300);  // 5 minutes

bool CRateLimiter::AllowRequest(const std::string& ipAddress) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Get or create record for this IP
    RequestRecord& record = GetRecord(ipAddress);

    // Check if window has expired - reset if so
    if (IsWindowExpired(record)) {
        record.count = 0;
        record.windowStart = std::chrono::steady_clock::now();
    }

    // Check if under rate limit
    if (record.count >= MAX_REQUESTS_PER_MINUTE) {
        return false;  // Rate limit exceeded
    }

    // Allow request and increment counter
    record.count++;
    return true;
}

void CRateLimiter::RecordAuthFailure(const std::string& ipAddress) {
    std::lock_guard<std::mutex> lock(m_mutex);

    RequestRecord& record = GetRecord(ipAddress);

    record.failedAttempts++;
    record.lastFailedTime = std::chrono::steady_clock::now();
}

void CRateLimiter::RecordAuthSuccess(const std::string& ipAddress) {
    std::lock_guard<std::mutex> lock(m_mutex);

    RequestRecord& record = GetRecord(ipAddress);

    // Reset failed attempt counter on successful auth
    record.failedAttempts = 0;
}

bool CRateLimiter::IsLockedOut(const std::string& ipAddress) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_records.find(ipAddress);
    if (it == m_records.end()) {
        return false;  // No record = not locked out
    }

    const RequestRecord& record = it->second;

    // Check if exceeded max failed attempts
    if (record.failedAttempts < MAX_FAILED_AUTH_ATTEMPTS) {
        return false;
    }

    // Check if lockout period has expired
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastFail = std::chrono::duration_cast<std::chrono::seconds>(
        now - record.lastFailedTime
    );

    if (timeSinceLastFail >= AUTH_LOCKOUT_DURATION) {
        return false;  // Lockout expired
    }

    return true;  // Still locked out
}

size_t CRateLimiter::GetRequestCount(const std::string& ipAddress) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_records.find(ipAddress);
    if (it == m_records.end()) {
        return 0;
    }

    const RequestRecord& record = it->second;

    // If window expired, return 0
    if (IsWindowExpired(record)) {
        return 0;
    }

    return record.count;
}

void CRateLimiter::CleanupOldRecords() {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto now = std::chrono::steady_clock::now();
    const std::chrono::hours ONE_HOUR(1);

    // Remove records older than 1 hour
    for (auto it = m_records.begin(); it != m_records.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::hours>(
            now - it->second.windowStart
        );

        if (age >= ONE_HOUR) {
            it = m_records.erase(it);
        } else {
            ++it;
        }
    }
}

// Private methods

CRateLimiter::RequestRecord& CRateLimiter::GetRecord(const std::string& ipAddress) {
    // If record doesn't exist, create it
    if (m_records.find(ipAddress) == m_records.end()) {
        RequestRecord newRecord;
        newRecord.count = 0;
        newRecord.windowStart = std::chrono::steady_clock::now();
        newRecord.failedAttempts = 0;
        newRecord.lastFailedTime = std::chrono::steady_clock::time_point::min();
        m_records[ipAddress] = newRecord;
    }

    return m_records[ipAddress];
}

bool CRateLimiter::IsWindowExpired(const RequestRecord& record) const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - record.windowStart
    );

    return elapsed >= WINDOW_DURATION;
}
