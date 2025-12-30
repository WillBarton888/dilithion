// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_ASYNC_BROADCASTER_H
#define DILITHION_NET_ASYNC_BROADCASTER_H

#include <net/serialize.h>
#include <primitives/block.h>  // For CBlockHeader (BIP 130 HEADERS announcements)
#include <uint256.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// Forward declaration
class CConnman;

/**
 * CAsyncBroadcaster - Asynchronous message broadcasting system
 *
 * Provides non-blocking message broadcasting to multiple peers with:
 * - Priority queue (blocks before transactions)
 * - Automatic retry with exponential backoff
 * - Background worker thread
 * - Statistics tracking
 * - Thread-safe operation
 *
 * Usage:
 *   CAsyncBroadcaster broadcaster(connman);
 *   broadcaster.Start();
 *   broadcaster.BroadcastBlock(block_hash, peer_ids);  // Returns immediately
 */
class CAsyncBroadcaster {
public:
    /**
     * Message priority levels (higher = more urgent)
     */
    enum Priority {
        PRIORITY_LOW = 0,        // Background sync, historical data
        PRIORITY_NORMAL = 1,     // Transactions, mempool
        PRIORITY_HIGH = 2,       // Blocks, urgent data
        PRIORITY_CRITICAL = 3    // Emergency messages, system alerts
    };

    /**
     * Broadcast task structure
     * Contains message, target peers, priority, and retry metadata
     */
    struct BroadcastTask {
        CNetMessage message;          // Message to broadcast
        std::vector<int> peer_ids;    // Target peer IDs
        Priority priority;            // Task priority
        int64_t queued_time;          // Timestamp when queued (milliseconds)
        int retry_count;              // Number of retry attempts

        /**
         * Comparison operator for priority queue
         * Higher priority tasks are processed first
         * Within same priority, FIFO order (older tasks first)
         */
        bool operator<(const BroadcastTask& other) const {
            if (priority != other.priority) {
                return priority < other.priority;  // Max heap - higher priority first
            }
            return queued_time > other.queued_time;  // FIFO within priority
        }
    };

    /**
     * Broadcast statistics
     */
    struct Stats {
        size_t queue_depth;           // Current queue size
        size_t total_queued;          // Total messages queued (lifetime)
        size_t total_sent;            // Total messages sent successfully
        size_t total_failed;          // Total messages failed permanently
        size_t total_retried;         // Total retry attempts
        double avg_queue_time_ms;     // Average time in queue (milliseconds)
        double send_rate_per_sec;     // Messages sent per second (recent)
    };

    /**
     * Constructor
     * @param connman Pointer to connection manager for sending messages
     */
    explicit CAsyncBroadcaster(CConnman* connman);

    /**
     * Destructor - ensures worker thread is stopped
     */
    ~CAsyncBroadcaster();

    // Disable copy/move to prevent issues with worker thread
    CAsyncBroadcaster(const CAsyncBroadcaster&) = delete;
    CAsyncBroadcaster& operator=(const CAsyncBroadcaster&) = delete;

    /**
     * Start the broadcaster worker thread
     * @return true if started successfully, false if already running
     */
    bool Start();

    /**
     * Stop the broadcaster worker thread
     * Waits for current task to complete, then flushes queue
     */
    void Stop();

    /**
     * Check if broadcaster is running
     * @return true if worker thread is active
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Queue a message for broadcast (non-blocking)
     * @param message Message to broadcast
     * @param peer_ids List of peer IDs to send to
     * @param priority Message priority (default: NORMAL)
     * @return true if queued successfully, false if queue is full
     */
    bool QueueBroadcast(const CNetMessage& message,
                       const std::vector<int>& peer_ids,
                       Priority priority = PRIORITY_NORMAL);

    /**
     * Queue a block broadcast (convenience wrapper for high-priority INV)
     * @param hash Block hash
     * @param peer_ids List of peer IDs to send to
     * @return true if queued successfully
     */
    bool BroadcastBlock(const uint256& hash, const std::vector<int>& peer_ids);

    /**
     * Queue a block broadcast with BIP 130 routing (HEADERS vs INV by peer preference)
     * @param hash Block hash
     * @param header Block header (for HEADERS message to preferring peers)
     * @param peer_ids List of peer IDs to send to
     * @return true if queued successfully
     */
    bool BroadcastBlock(const uint256& hash, const CBlockHeader& header, const std::vector<int>& peer_ids);

    /**
     * Get current broadcast statistics
     * @return Stats structure with current metrics
     */
    Stats GetStats() const;

    /**
     * Set maximum queue depth
     * @param max_depth Maximum number of tasks in queue
     */
    void SetMaxQueueDepth(size_t max_depth) { m_max_queue_depth.store(max_depth); }

    /**
     * Set maximum retry attempts
     * @param max_retries Maximum number of retries per task (0 = no retries)
     */
    void SetMaxRetries(int max_retries) { m_max_retries.store(max_retries); }

    /**
     * Set retry delay
     * @param delay_ms Base delay in milliseconds (exponential backoff applied)
     */
    void SetRetryDelay(int delay_ms) { m_retry_delay_ms.store(delay_ms); }

private:
    /**
     * Worker thread main loop
     * Processes tasks from queue until stopped
     */
    void WorkerThread();

    /**
     * Process a single broadcast task
     * @param task Task to process
     * @return true if all sends succeeded, false if any failed
     */
    bool ProcessTask(const BroadcastTask& task);

    /**
     * Check if task should be retried
     * @param task Task to check
     * @return true if should retry, false if exceeded max retries
     */
    bool ShouldRetry(const BroadcastTask& task) const;

    /**
     * Calculate retry delay with exponential backoff
     * @param retry_count Number of retries attempted
     * @return Delay in milliseconds
     */
    int64_t GetRetryDelay(int retry_count) const;

    /**
     * Update statistics (called after each task)
     * @param task_duration_ms Time taken to process task
     * @param success true if task succeeded
     */
    void UpdateStats(int64_t task_duration_ms, bool success);

    // Connection manager pointer
    CConnman* m_connman;

    // Task queue (priority queue for task ordering)
    std::priority_queue<BroadcastTask> m_queue;
    mutable std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // Worker thread
    std::thread m_worker;
    std::atomic<bool> m_running{false};

    // Statistics (thread-safe atomics where possible)
    mutable std::mutex m_stats_mutex;
    Stats m_stats{0, 0, 0, 0, 0, 0.0, 0.0};

    // Statistics tracking for rate calculation
    int64_t m_stats_window_start{0};   // Start of current measurement window
    size_t m_stats_window_sent{0};     // Messages sent in current window

    // Configuration (atomic for thread-safe access)
    std::atomic<size_t> m_max_queue_depth{1000};  // Max queue size
    std::atomic<int> m_max_retries{3};            // Max retry attempts
    std::atomic<int> m_retry_delay_ms{1000};      // Base retry delay (ms)
};

/**
 * Global async broadcaster instance (initialized in dilithion-node.cpp)
 */
extern CAsyncBroadcaster* g_async_broadcaster;

#endif // DILITHION_NET_ASYNC_BROADCASTER_H
