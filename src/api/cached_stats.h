// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_API_CACHED_STATS_H
#define DILITHION_API_CACHED_STATS_H

#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <functional>

/**
 * CCachedChainStats - Lock-free cached chain statistics for API
 *
 * STRESS TEST FIX: Issue 2 - HTTP API unresponsive during load.
 * Provides cached statistics that can be read without blocking,
 * even when the validation thread holds the chain state lock.
 *
 * Statistics are updated every second by a background thread.
 * All values are atomic and can be read safely from any thread.
 *
 * Usage:
 *   CCachedChainStats cached_stats;
 *   cached_stats.Start([&]() {
 *       return CCachedChainStats::UpdateData{...};
 *   });
 *
 *   // In HTTP handler:
 *   int height = cached_stats.GetHeight();  // Never blocks
 *
 * Reference: Pattern from Bitcoin Core PR #15932 (minimize cs_main lock time)
 */
class CCachedChainStats {
public:
    /**
     * Data structure for atomic update
     */
    struct UpdateData {
        int block_height{0};
        int headers_height{0};
        int peer_count{0};
        uint32_t difficulty{0};
        int64_t last_block_time{0};
        bool is_syncing{false};
    };

    /**
     * Update callback function type
     * Should return current chain state (will be called from background thread)
     */
    using UpdateCallback = std::function<UpdateData()>;

    /**
     * Constructor
     */
    CCachedChainStats();

    /**
     * Destructor - stops background thread
     */
    ~CCachedChainStats();

    // Non-copyable, non-movable
    CCachedChainStats(const CCachedChainStats&) = delete;
    CCachedChainStats& operator=(const CCachedChainStats&) = delete;

    /**
     * Start the background update thread
     * @param callback Function to call to get current chain state
     * @return true on success, false if already running
     */
    bool Start(UpdateCallback callback);

    /**
     * Stop the background update thread
     */
    void Stop();

    /**
     * Check if running
     */
    bool IsRunning() const { return m_running.load(); }

    // Lock-free getters for cached values (NEVER block)
    int GetHeight() const { return m_block_height.load(); }
    int GetHeadersHeight() const { return m_headers_height.load(); }
    int GetPeerCount() const { return m_peer_count.load(); }
    uint32_t GetDifficulty() const { return m_difficulty.load(); }
    int64_t GetLastBlockTime() const { return m_last_block_time.load(); }
    bool IsSyncing() const { return m_is_syncing.load(); }

    /**
     * Get age of cached data in seconds
     */
    int64_t GetCacheAge() const {
        auto now = std::chrono::system_clock::now();
        auto cache_time = std::chrono::system_clock::time_point(
            std::chrono::seconds(m_cache_time.load()));
        return std::chrono::duration_cast<std::chrono::seconds>(now - cache_time).count();
    }

    /**
     * Generate JSON stats string (lock-free)
     * @param network Network name (testnet/mainnet)
     * @return JSON string with current stats
     */
    std::string ToJSON(const std::string& network) const;

    // Configuration
    static constexpr int64_t UPDATE_INTERVAL_MS = 1000;  // Update every 1 second

private:
    /**
     * Background update thread
     */
    void UpdateThread();

    // Thread control
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shutdown{false};
    UpdateCallback m_callback;

    // Cached values (all atomic for lock-free reads)
    std::atomic<int> m_block_height{0};
    std::atomic<int> m_headers_height{0};
    std::atomic<int> m_peer_count{0};
    std::atomic<uint32_t> m_difficulty{0};
    std::atomic<int64_t> m_last_block_time{0};
    std::atomic<bool> m_is_syncing{false};
    std::atomic<int64_t> m_cache_time{0};
};

#endif // DILITHION_API_CACHED_STATS_H
