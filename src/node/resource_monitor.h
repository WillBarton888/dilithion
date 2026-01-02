// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_RESOURCE_MONITOR_H
#define DILITHION_NODE_RESOURCE_MONITOR_H

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>
#include <cstdint>

/**
 * @brief Memory pressure response for stress test resilience
 *
 * Phase 3.3: Monitors system resources and triggers cleanup when memory
 * pressure is detected. This prevents OOM conditions during stress tests
 * or when processing large numbers of orphan blocks.
 *
 * Pressure levels:
 * - Normal (< 80%): No action
 * - Warning (80-90%): Light cleanup (evict oldest orphans)
 * - Critical (> 90%): Aggressive cleanup (clear orphans, trim mempool)
 *
 * Usage:
 *   CResourceMonitor monitor;
 *   monitor.SetMemoryLimit(2ULL * 1024 * 1024 * 1024);  // 2GB
 *   monitor.SetCleanupCallback([](int level) {
 *       if (level >= 2) {
 *           g_orphan_manager.Clear();
 *           g_mempool.Clear();
 *       } else if (level == 1) {
 *           // Light cleanup
 *       }
 *   });
 *   monitor.Start();
 */
class CResourceMonitor {
public:
    /**
     * @brief Cleanup callback type
     * @param level Pressure level: 0=normal, 1=warning, 2=critical
     */
    using CleanupCallback = std::function<void(int level)>;

    /**
     * @brief Constructor
     */
    CResourceMonitor();

    /**
     * @brief Destructor - stops monitor thread
     */
    ~CResourceMonitor();

    // Non-copyable, non-movable
    CResourceMonitor(const CResourceMonitor&) = delete;
    CResourceMonitor& operator=(const CResourceMonitor&) = delete;
    CResourceMonitor(CResourceMonitor&&) = delete;
    CResourceMonitor& operator=(CResourceMonitor&&) = delete;

    /**
     * @brief Start the resource monitor thread
     * @return true on success, false if already running
     */
    bool Start();

    /**
     * @brief Stop the resource monitor thread
     */
    void Stop();

    /**
     * @brief Check if monitor is running
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * @brief Set the memory limit in bytes
     * @param limit Maximum memory usage before cleanup triggers
     */
    void SetMemoryLimit(size_t limit) { m_memory_limit = limit; }

    /**
     * @brief Get the memory limit
     */
    size_t GetMemoryLimit() const { return m_memory_limit; }

    /**
     * @brief Set cleanup callback
     * @param callback Function called when cleanup is needed
     */
    void SetCleanupCallback(CleanupCallback callback);

    /**
     * @brief Get current memory usage in bytes
     */
    size_t GetCurrentMemoryUsage() const;

    /**
     * @brief Get current pressure level (0=normal, 1=warning, 2=critical)
     */
    int GetPressureLevel() const { return m_current_level.load(); }

    /**
     * @brief Get number of cleanups triggered
     */
    int64_t GetCleanupCount() const { return m_cleanup_count.load(); }

    /**
     * @brief Manually trigger a memory check (for testing)
     */
    void CheckMemoryPressure();

    // Configuration constants
    static constexpr int64_t CHECK_INTERVAL_MS = 5000;   // Check every 5 seconds
    static constexpr double WARNING_THRESHOLD = 0.80;    // 80% triggers warning
    static constexpr double CRITICAL_THRESHOLD = 0.90;   // 90% triggers critical

private:
    /**
     * @brief Monitor thread main loop
     */
    void MonitorThread();

    /**
     * @brief Get process RSS (Resident Set Size) in bytes
     * Platform-specific implementation
     */
    size_t GetProcessRSS() const;

    // Thread control
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shutdown{false};

    // Configuration
    size_t m_memory_limit{2ULL * 1024 * 1024 * 1024};  // Default 2GB

    // Callback
    CleanupCallback m_cleanup_callback;
    mutable std::mutex m_callback_mutex;

    // Statistics
    std::atomic<int> m_current_level{0};
    std::atomic<int64_t> m_cleanup_count{0};
    std::atomic<size_t> m_last_rss{0};
};

// Global instance (set by node initialization)
extern CResourceMonitor* g_resource_monitor;

#endif // DILITHION_NODE_RESOURCE_MONITOR_H
