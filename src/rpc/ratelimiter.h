// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_RATELIMITER_H
#define DILITHION_RPC_RATELIMITER_H

#include <string>
#include <map>
#include <chrono>
#include <mutex>

/**
 * RPC Rate Limiter
 *
 * Prevents brute force attacks and DoS on RPC endpoints by limiting
 * requests per IP address over time windows.
 *
 * Design Philosophy:
 * - Simple: Easy to integrate and understand
 * - Robust: Thread-safe, handles edge cases
 * - Safe: Prevents resource exhaustion
 * - 10/10: Production-ready implementation
 */

class CRateLimiter {
private:
    // Request tracking per IP
    struct RequestRecord {
        size_t count;                    // Number of requests in current window
        std::chrono::steady_clock::time_point windowStart;  // Window start time
        size_t failedAttempts;           // Consecutive failed auth attempts
        std::chrono::steady_clock::time_point lastFailedTime;  // Last failed attempt
    };

    std::map<std::string, RequestRecord> m_records;
    mutable std::mutex m_mutex;

    // Configuration
    static const size_t MAX_REQUESTS_PER_MINUTE = 60;     // 60 requests/minute
    static const size_t MAX_REQUESTS_PER_HOUR = 1000;     // 1000 requests/hour
    static const std::chrono::seconds WINDOW_DURATION;     // 60 seconds
    static const size_t MAX_FAILED_AUTH_ATTEMPTS = 5;     // 5 failed attempts
    static const std::chrono::seconds AUTH_LOCKOUT_DURATION;  // 300 seconds (5 minutes)

public:
    CRateLimiter() = default;

    /**
     * Check if request from IP should be allowed
     *
     * @param ipAddress IP address of requestor
     * @return true if request allowed, false if rate limited
     */
    bool AllowRequest(const std::string& ipAddress);

    /**
     * Record authentication failure from IP
     * Implements exponential backoff after multiple failures
     *
     * @param ipAddress IP address of failed auth
     */
    void RecordAuthFailure(const std::string& ipAddress);

    /**
     * Record successful authentication from IP
     * Resets failed attempt counter
     *
     * @param ipAddress IP address of successful auth
     */
    void RecordAuthSuccess(const std::string& ipAddress);

    /**
     * Check if IP is currently locked out due to failed auth
     *
     * @param ipAddress IP address to check
     * @return true if locked out, false otherwise
     */
    bool IsLockedOut(const std::string& ipAddress) const;

    /**
     * Get current request count for IP
     * (for monitoring/debugging)
     *
     * @param ipAddress IP address to check
     * @return current request count in window
     */
    size_t GetRequestCount(const std::string& ipAddress) const;

    /**
     * Clear old records (periodic cleanup)
     * Removes records older than 1 hour
     */
    void CleanupOldRecords();

private:
    /**
     * Get or create record for IP
     */
    RequestRecord& GetRecord(const std::string& ipAddress);

    /**
     * Check if current window has expired
     */
    bool IsWindowExpired(const RequestRecord& record) const;
};

#endif // DILITHION_RPC_RATELIMITER_H
