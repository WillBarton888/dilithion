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
    // FIX-013 (RPC-002): Per-method rate limit configuration
    struct MethodRateLimit {
        double capacity;          // Max burst tokens
        double refillRate;        // Tokens per second
        double costPerRequest;    // Cost per request (usually 1.0)
    };

    // Request tracking per IP
    struct RequestRecord {
        // RPC-008 FIX: Token bucket rate limiting (prevents burst attacks)
        double tokens;                   // Current token balance (burst allowance)
        std::chrono::steady_clock::time_point lastRefill;  // Last token refill time

        // FIX-013 (RPC-002): Per-method rate limiting
        std::map<std::string, double> methodTokens;  // Per-method token buckets
        std::map<std::string, std::chrono::steady_clock::time_point> methodRefillTimes;

        // RPC-006 FIX: Exponential backoff tracking
        size_t failedAttempts;           // Consecutive failed auth attempts
        size_t lockoutCount;             // Number of times locked out (for exponential backoff)
        std::chrono::steady_clock::time_point lastFailedTime;  // Last failed attempt

        // Legacy fields (kept for compatibility)
        size_t count;                    // Number of requests in current window
        std::chrono::steady_clock::time_point windowStart;  // Window start time
    };

    std::map<std::string, RequestRecord> m_records;
    mutable std::mutex m_mutex;

    // RPC-008 FIX: Token bucket configuration (prevents burst DoS)
    static constexpr double TOKEN_BUCKET_CAPACITY = 10.0;    // Max burst: 10 requests instantly
    static constexpr double TOKEN_REFILL_RATE = 1.0;         // 1 token/second = 60/minute steady
    static constexpr double TOKEN_COST_PER_REQUEST = 1.0;    // Each request costs 1 token

    // Configuration
    static const size_t MAX_REQUESTS_PER_MINUTE = 60;     // 60 requests/minute (steady state)
    static const size_t MAX_REQUESTS_PER_HOUR = 1000;     // 1000 requests/hour
    static const std::chrono::seconds WINDOW_DURATION;     // 60 seconds
    static const size_t MAX_FAILED_AUTH_ATTEMPTS = 5;     // 5 failed attempts before lockout

    // RPC-006 FIX: Exponential backoff durations
    static const std::chrono::seconds AUTH_LOCKOUT_BASE;     // 60 seconds (1 minute base)
    static const std::chrono::seconds AUTH_LOCKOUT_MAX;      // 900 seconds (15 minutes max)

    // FIX-013 (RPC-002): Per-method rate limit definitions
    static const std::map<std::string, MethodRateLimit> METHOD_LIMITS;
    static const MethodRateLimit DEFAULT_METHOD_LIMIT;

public:
    CRateLimiter() = default;

    /**
     * Check if request from IP should be allowed (global rate limit)
     *
     * @param ipAddress IP address of requestor
     * @return true if request allowed, false if rate limited
     */
    bool AllowRequest(const std::string& ipAddress);

    /**
     * FIX-013 (RPC-002): Check if method request from IP should be allowed
     *
     * Implements per-method rate limiting with independent token buckets
     * for each RPC method. Sensitive methods (walletpassphrase, sendtoaddress)
     * have stricter limits than read-only methods (getbalance, getblockcount).
     *
     * Token Bucket Algorithm:
     * - Each method has its own capacity and refill rate
     * - Tokens refill continuously at configured rate
     * - Request consumes 1 token, rejected if insufficient tokens
     *
     * @param ipAddress IP address of requestor
     * @param method RPC method name (e.g., "walletpassphrase", "getbalance")
     * @return true if request allowed, false if rate limited
     */
    bool AllowMethodRequest(const std::string& ipAddress, const std::string& method);

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

    /**
     * FIX-013 (RPC-002): Get rate limit for specific method
     * Returns method-specific limit or default if not configured
     */
    const MethodRateLimit& GetMethodLimit(const std::string& method) const;
};

#endif // DILITHION_RPC_RATELIMITER_H
