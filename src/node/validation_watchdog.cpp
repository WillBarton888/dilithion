// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/validation_watchdog.h>

#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

CValidationWatchdog::CValidationWatchdog() = default;

CValidationWatchdog::~CValidationWatchdog() {
    Stop();
}

bool CValidationWatchdog::Start() {
    if (m_running.load()) {
        return false;  // Already running
    }

    m_shutdown.store(false);
    m_running.store(true);
    m_thread = std::thread(&CValidationWatchdog::WatchdogThread, this);

    std::cout << "[ValidationWatchdog] Started with " << VALIDATION_TIMEOUT_SECONDS
              << "s timeout, checking every " << CHECK_INTERVAL_MS << "ms" << std::endl;

    return true;
}

void CValidationWatchdog::Stop() {
    if (!m_running.load()) {
        return;  // Already stopped
    }

    m_shutdown.store(true);
    m_running.store(false);

    if (m_thread.joinable()) {
        m_thread.join();
    }

    std::cout << "[ValidationWatchdog] Stopped (detected " << m_timeout_count.load()
              << " timeout(s) during session)" << std::endl;
}

void CValidationWatchdog::ReportValidationStart(const uint256& hash, int height) {
    // Get current time as Unix timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    // Store hash as two 64-bit values for atomic access
    // This avoids needing a mutex for the common path
    const uint64_t* hash_data = reinterpret_cast<const uint64_t*>(hash.begin());
    m_current_hash_low.store(hash_data[0]);
    m_current_hash_high.store(hash_data[1]);

    // Store height and start time
    m_current_height.store(height);
    m_validation_start_time.store(timestamp);
}

void CValidationWatchdog::ReportValidationComplete() {
    // Get completion time
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    // Clear current validation state
    m_validation_start_time.store(0);
    m_current_height.store(-1);
    m_current_hash_low.store(0);
    m_current_hash_high.store(0);

    // Update last complete time
    m_last_complete_time.store(timestamp);
}

void CValidationWatchdog::SetTimeoutCallback(TimeoutCallback callback) {
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_timeout_callback = std::move(callback);
}

void CValidationWatchdog::SetRecoveryCallback(RecoveryCallback callback) {
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_recovery_callback = std::move(callback);
}

bool CValidationWatchdog::GetCurrentValidation(uint256& hash, int& height, int64_t& start_time) const {
    start_time = m_validation_start_time.load();
    if (start_time == 0) {
        // Not currently validating
        hash = uint256();  // Clear hash
        height = -1;
        return false;
    }

    height = m_current_height.load();

    // Reconstruct hash from two 64-bit values
    uint64_t* hash_data = reinterpret_cast<uint64_t*>(hash.begin());
    hash_data[0] = m_current_hash_low.load();
    hash_data[1] = m_current_hash_high.load();
    // Note: uint256 is 32 bytes = 4 uint64_t, but we only store first 2
    // This is enough for logging/identification purposes
    hash_data[2] = 0;
    hash_data[3] = 0;

    return true;
}

void CValidationWatchdog::WatchdogThread() {
    while (!m_shutdown.load()) {
        // Sleep for check interval
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL_MS));

        if (m_shutdown.load()) {
            break;
        }

        // Check if validation is stuck
        int64_t start_time = m_validation_start_time.load();
        if (start_time == 0) {
            continue;  // Not currently validating
        }

        // Get current time
        auto now = std::chrono::system_clock::now();
        auto current_time = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        int64_t elapsed_seconds = current_time - start_time;

        if (elapsed_seconds > VALIDATION_TIMEOUT_SECONDS) {
            // Validation is stuck!
            int height = m_current_height.load();

            // Reconstruct hash for logging
            uint256 hash;
            uint64_t* hash_data = reinterpret_cast<uint64_t*>(hash.begin());
            hash_data[0] = m_current_hash_low.load();
            hash_data[1] = m_current_hash_high.load();
            hash_data[2] = 0;
            hash_data[3] = 0;

            // Increment timeout counter
            m_timeout_count.fetch_add(1);

            // Call timeout handler
            HandleTimeout(hash, height, elapsed_seconds);

            // Check for custom callback
            {
                std::lock_guard<std::mutex> lock(m_callback_mutex);
                if (m_timeout_callback) {
                    m_timeout_callback(hash, height, elapsed_seconds);
                }
            }

            // Phase 3.3: Attempt automatic recovery if enabled
            bool recovery_succeeded = false;
            if (m_recovery_enabled.load()) {
                m_recovery_attempts.fetch_add(1);

                std::cout << "[ValidationWatchdog] Attempting automatic recovery for stuck block at height "
                          << height << "..." << std::endl;

                RecoveryCallback callback;
                {
                    std::lock_guard<std::mutex> lock(m_callback_mutex);
                    callback = m_recovery_callback;
                }

                if (callback) {
                    try {
                        recovery_succeeded = callback(hash, height);
                        if (recovery_succeeded) {
                            m_recovery_successes.fetch_add(1);
                            std::cout << "[ValidationWatchdog] Recovery SUCCESSFUL - skipped stuck block and continuing"
                                      << std::endl;
                            // Clear validation state since we're skipping this block
                            ReportValidationComplete();
                        } else {
                            std::cerr << "[ValidationWatchdog] Recovery FAILED - callback returned false"
                                      << std::endl;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "[ValidationWatchdog] Recovery EXCEPTION: " << e.what() << std::endl;
                    }
                } else {
                    std::cerr << "[ValidationWatchdog] Recovery FAILED - no callback registered"
                              << std::endl;
                }
            }

            // Don't spam - wait longer before next check for same block
            // The block might eventually complete or the node might need restart
            // If recovery succeeded, continue immediately
            if (!recovery_succeeded) {
                std::this_thread::sleep_for(std::chrono::seconds(VALIDATION_TIMEOUT_SECONDS));
            }
        }
    }
}

void CValidationWatchdog::HandleTimeout(const uint256& hash, int height, int64_t elapsed_seconds) {
    // Format current time for logging
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_now;
#ifdef _WIN32
    localtime_s(&tm_now, &time_t_now);
#else
    localtime_r(&time_t_now, &tm_now);
#endif

    std::ostringstream time_str;
    time_str << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");

    // Log critical error
    std::cerr << "\n"
              << "===============================================================================\n"
              << "[CRITICAL] VALIDATION TIMEOUT DETECTED\n"
              << "===============================================================================\n"
              << "Time:        " << time_str.str() << "\n"
              << "Block Hash:  " << hash.GetHex().substr(0, 32) << "...\n"
              << "Block Height: " << height << "\n"
              << "Elapsed:     " << elapsed_seconds << " seconds (timeout: "
              << VALIDATION_TIMEOUT_SECONDS << "s)\n"
              << "-------------------------------------------------------------------------------\n"
              << "Possible Causes:\n"
              << "  1. RandomX PoW verification hanging\n"
              << "  2. Deadlock in validation thread\n"
              << "  3. Uncaught exception in validation code\n"
              << "  4. System resource exhaustion (memory, disk I/O)\n"
              << "-------------------------------------------------------------------------------\n"
              << "Auto-Recovery: " << (m_recovery_enabled.load() ? "ENABLED" : "DISABLED") << "\n"
              << "Recovery Stats: " << m_recovery_successes.load() << "/" << m_recovery_attempts.load()
              << " successful\n"
              << "-------------------------------------------------------------------------------\n"
              << "Recommended Actions:\n"
              << "  1. Check system resources (memory, disk, CPU)\n"
              << "  2. Restart node if validation remains stuck\n"
              << "  3. Report issue with block hash and debug logs\n"
              << "===============================================================================\n"
              << std::endl;

    // Also log to standard output for log files
    std::cout << "[ValidationWatchdog] TIMEOUT: Block " << hash.GetHex().substr(0, 16)
              << "... at height " << height << " stuck for " << elapsed_seconds
              << "s (timeout count: " << m_timeout_count.load() << ")" << std::endl;
}
