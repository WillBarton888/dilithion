// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_MESSAGE_QUEUE_H
#define DILITHION_NET_MESSAGE_QUEUE_H

#include <net/serialize.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// Forward declaration
class CNetMessageProcessor;

/**
 * CMessageProcessorQueue - Async message processing queue
 *
 * Decouples network I/O from message processing to prevent blocking:
 * - I/O thread enqueues messages (non-blocking)
 * - Worker thread(s) process messages in background
 * - Priority queue (blocks > headers > transactions)
 * - Back-pressure when queue full
 *
 * This fixes BUG #125: Header processing blocking network thread
 *
 * Usage:
 *   CMessageProcessorQueue queue(message_processor);
 *   queue.Start();
 *   queue.EnqueueMessage(peer_id, message);  // Returns immediately
 */
class CMessageProcessorQueue {
public:
    /**
     * Message priority levels (higher = more urgent)
     */
    enum Priority {
        PRIORITY_LOW = 0,        // Addr, ping, pong
        PRIORITY_NORMAL = 1,     // Transactions, getdata
        PRIORITY_HIGH = 2,       // Headers (IBD)
        PRIORITY_CRITICAL = 3    // Blocks
    };

    /**
     * Queued message structure
     */
    struct QueuedMessage {
        int peer_id;              // Source peer
        CNetMessage message;      // Message to process
        Priority priority;        // Processing priority
        int64_t queued_time;      // Timestamp when queued (milliseconds)

        /**
         * Comparison operator for priority queue
         * Higher priority tasks processed first
         * Within same priority, FIFO order (older first)
         */
        bool operator<(const QueuedMessage& other) const {
            if (priority != other.priority) {
                return priority < other.priority;  // Max heap - higher priority first
            }
            return queued_time > other.queued_time;  // FIFO within priority
        }
    };

    /**
     * Queue statistics
     */
    struct Stats {
        size_t queue_depth;           // Current queue size
        size_t total_queued;          // Total messages queued (lifetime)
        size_t total_processed;       // Total messages processed
        size_t total_dropped;         // Total messages dropped (queue full)
        double avg_queue_time_ms;     // Average time in queue (milliseconds)
        double process_rate_per_sec;  // Messages processed per second (recent)
    };

    /**
     * Constructor
     * @param msg_proc Reference to message processor
     * @param num_workers Number of worker threads (default 1)
     */
    explicit CMessageProcessorQueue(CNetMessageProcessor& msg_proc,
                                    size_t num_workers = 1);

    /**
     * Destructor - ensures worker threads are stopped
     */
    ~CMessageProcessorQueue();

    // Disable copy/move
    CMessageProcessorQueue(const CMessageProcessorQueue&) = delete;
    CMessageProcessorQueue& operator=(const CMessageProcessorQueue&) = delete;

    /**
     * Start worker thread(s)
     * @return true if started successfully
     */
    bool Start();

    /**
     * Stop worker thread(s)
     * Waits for current processing to complete
     */
    void Stop();

    /**
     * Check if queue is running
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Enqueue message for async processing (non-blocking)
     * @param peer_id Source peer ID
     * @param message Message to process
     * @param priority Processing priority
     * @return true if queued, false if queue full
     */
    bool EnqueueMessage(int peer_id, const CNetMessage& message,
                        Priority priority = PRIORITY_NORMAL);

    /**
     * Determine priority based on message command
     * @param message Message to check
     * @return Appropriate priority level
     */
    static Priority GetMessagePriority(const CNetMessage& message);

    /**
     * Get current statistics
     */
    Stats GetStats() const;

    /**
     * Set maximum queue depth
     */
    void SetMaxQueueDepth(size_t max_depth) { m_max_queue_depth.store(max_depth); }

private:
    /**
     * Worker thread main loop
     */
    void WorkerThread();

    /**
     * Process a single message
     * @return true if processed successfully
     */
    bool ProcessQueuedMessage(const QueuedMessage& msg);

    /**
     * Update statistics
     */
    void UpdateStats(int64_t queue_time_ms, bool success);

    // Message processor reference
    CNetMessageProcessor& m_message_processor;

    // Task queue
    std::priority_queue<QueuedMessage> m_queue;
    mutable std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // Worker threads
    std::vector<std::thread> m_workers;
    std::atomic<bool> m_running{false};
    size_t m_num_workers;

    // Statistics
    mutable std::mutex m_stats_mutex;
    Stats m_stats{0, 0, 0, 0, 0.0, 0.0};
    int64_t m_stats_window_start{0};
    size_t m_stats_window_processed{0};

    // Configuration
    std::atomic<size_t> m_max_queue_depth{10000};
};

/**
 * Global message queue instance
 */
extern std::atomic<CMessageProcessorQueue*> g_message_queue;

#endif // DILITHION_NET_MESSAGE_QUEUE_H
