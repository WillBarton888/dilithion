// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_VALIDATION_WATCHDOG_H
#define DILITHION_NODE_VALIDATION_WATCHDOG_H

#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <functional>
#include <mutex>

#include <uint256.h>

/**
 * @brief Watchdog to detect frozen validation threads
 *
 * The validation watchdog monitors the block validation queue for stuck
 * validation operations. If a block takes longer than VALIDATION_TIMEOUT_SECONDS
 * to validate, the watchdog logs a critical error with the block details.
 *
 * This addresses Issue 1 from the 2026-01-01 stress test failure report:
 * - ValidationQueue starts processing a block but never completes
 * - Log shows: "[ValidationQueue] Processing block ... at height X" with no
 *   subsequent "Successfully validated" message
 * - Chain height stops advancing
 *
 * Usage:
 *   CValidationWatchdog watchdog;
 *   watchdog.Start();
 *
 *   // In validation thread:
 *   watchdog.ReportValidationStart(blockHash, height);
 *   // ... validate block ...
 *   watchdog.ReportValidationComplete();
 *
 *   // On shutdown:
 *   watchdog.Stop();
 *
 * Reference: Custom implementation (Bitcoin Core uses cooperative CCheckQueue)
 */
class CValidationWatchdog {
public:
    /**
     * @brief Callback type for timeout handling
     *
     * Parameters:
     * - uint256 blockHash: Hash of the stuck block
     * - int height: Height of the stuck block
     * - int64_t elapsed_seconds: How long validation has been running
     */
    using TimeoutCallback = std::function<void(const uint256&, int, int64_t)>;

    /**
     * @brief Callback type for automatic recovery
     *
     * Phase 3.3: Resilience feature - automatic validation recovery.
     * When called, should skip the stuck block and continue with next block.
     *
     * Parameters:
     * - uint256 blockHash: Hash of the stuck block to skip
     * - int height: Height of the stuck block
     *
     * Returns:
     * - true if recovery was successful
     * - false if recovery failed (e.g., queue empty)
     */
    using RecoveryCallback = std::function<bool(const uint256&, int)>;

    /**
     * @brief Constructor
     */
    CValidationWatchdog();

    /**
     * @brief Destructor - stops watchdog thread
     */
    ~CValidationWatchdog();

    // Non-copyable, non-movable
    CValidationWatchdog(const CValidationWatchdog&) = delete;
    CValidationWatchdog& operator=(const CValidationWatchdog&) = delete;
    CValidationWatchdog(CValidationWatchdog&&) = delete;
    CValidationWatchdog& operator=(CValidationWatchdog&&) = delete;

    /**
     * @brief Start the watchdog thread
     * @return true on success, false if already running
     */
    bool Start();

    /**
     * @brief Stop the watchdog thread
     */
    void Stop();

    /**
     * @brief Check if watchdog is running
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * @brief Report that validation has started for a block
     *
     * Call this immediately before starting block validation.
     * The watchdog will monitor this block until ReportValidationComplete() is called.
     *
     * @param hash Block hash being validated
     * @param height Block height being validated
     */
    void ReportValidationStart(const uint256& hash, int height);

    /**
     * @brief Report that validation has completed
     *
     * Call this immediately after block validation completes (success or failure).
     * Clears the current block tracking.
     */
    void ReportValidationComplete();

    /**
     * @brief Set custom timeout callback
     *
     * By default, the watchdog logs a critical error. You can override
     * this to add custom behavior (metrics, alerts, recovery attempts).
     *
     * @param callback Function to call when timeout is detected
     */
    void SetTimeoutCallback(TimeoutCallback callback);

    /**
     * @brief Enable automatic recovery on timeout
     *
     * Phase 3.3: When enabled, the watchdog will attempt to skip stuck blocks
     * and continue validation. This prevents a single bad block from stalling
     * the entire node.
     *
     * @param enabled true to enable, false to disable
     */
    void SetAutoRecoveryEnabled(bool enabled) { m_recovery_enabled.store(enabled); }

    /**
     * @brief Check if auto recovery is enabled
     */
    bool IsAutoRecoveryEnabled() const { return m_recovery_enabled.load(); }

    /**
     * @brief Set recovery callback
     *
     * The callback should skip the stuck block and signal the validation queue
     * to continue with the next block.
     *
     * @param callback Function to call for recovery
     */
    void SetRecoveryCallback(RecoveryCallback callback);

    /**
     * @brief Get recovery attempt count
     */
    int64_t GetRecoveryAttemptCount() const { return m_recovery_attempts.load(); }

    /**
     * @brief Get successful recovery count
     */
    int64_t GetRecoverySuccessCount() const { return m_recovery_successes.load(); }

    /**
     * @brief Get current validation state for diagnostics
     *
     * @param[out] hash Hash of block currently being validated (or zero if idle)
     * @param[out] height Height of block currently being validated (or -1 if idle)
     * @param[out] start_time Start time of current validation (or 0 if idle)
     * @return true if currently validating, false if idle
     */
    bool GetCurrentValidation(uint256& hash, int& height, int64_t& start_time) const;

    /**
     * @brief Get timeout detection count
     */
    int64_t GetTimeoutCount() const { return m_timeout_count.load(); }

    // Configuration constants
    static constexpr int64_t VALIDATION_TIMEOUT_SECONDS = 60;  // 1 minute timeout
    static constexpr int64_t CHECK_INTERVAL_MS = 5000;         // Check every 5 seconds

private:
    /**
     * @brief Watchdog thread main loop
     */
    void WatchdogThread();

    /**
     * @brief Default timeout handler - logs critical error
     */
    void HandleTimeout(const uint256& hash, int height, int64_t elapsed_seconds);

    // Thread control
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shutdown{false};

    // Current validation state (atomically updated)
    std::atomic<int64_t> m_validation_start_time{0};  // Unix timestamp when validation started
    std::atomic<int> m_current_height{-1};            // Height of block being validated
    std::atomic<uint64_t> m_current_hash_low{0};      // Low 64 bits of block hash
    std::atomic<uint64_t> m_current_hash_high{0};     // High 64 bits of block hash

    // Statistics
    std::atomic<int64_t> m_timeout_count{0};          // Number of timeouts detected
    std::atomic<int64_t> m_last_complete_time{0};     // Last successful validation time

    // Optional custom timeout callback
    TimeoutCallback m_timeout_callback;

    // Phase 3.3: Automatic recovery support
    std::atomic<bool> m_recovery_enabled{false};    // Enable auto-recovery on timeout
    RecoveryCallback m_recovery_callback;            // Callback to skip stuck block
    std::atomic<int64_t> m_recovery_attempts{0};    // Number of recovery attempts
    std::atomic<int64_t> m_recovery_successes{0};   // Number of successful recoveries

    // Mutex for callback access (rarely contended)
    mutable std::mutex m_callback_mutex;
};

#endif // DILITHION_NODE_VALIDATION_WATCHDOG_H
