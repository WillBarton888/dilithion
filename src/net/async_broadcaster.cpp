// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/async_broadcaster.h>
#include <net/net.h>
#include <net/protocol.h>
#include <iostream>
#include <chrono>

// Helper function to get current time in milliseconds
static int64_t GetTimeMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// External message processor (defined in net.cpp)
extern CNetMessageProcessor* g_message_processor;

// Constructor
CAsyncBroadcaster::CAsyncBroadcaster(CConnectionManager& conn_mgr)
    : m_connection_manager(conn_mgr) {
}

// Destructor
CAsyncBroadcaster::~CAsyncBroadcaster() {
    Stop();
}

// Start the broadcaster worker thread
bool CAsyncBroadcaster::Start() {
    if (m_running.load()) {
        std::cerr << "[AsyncBroadcaster] Already running" << std::endl;
        return false;
    }

    m_running.store(true);

    // CID 1675305 FIX: Acquire lock before modifying shared statistics data
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats_window_start = GetTimeMillis();
        m_stats_window_sent = 0;
    }

    // Launch worker thread
    try {
        m_worker = std::thread(&CAsyncBroadcaster::WorkerThread, this);
        std::cout << "[AsyncBroadcaster] Started successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        m_running.store(false);
        std::cerr << "[AsyncBroadcaster] Failed to start worker thread: " << e.what() << std::endl;
        return false;
    }
}

// Stop the broadcaster worker thread
void CAsyncBroadcaster::Stop() {
    if (!m_running.load()) {
        return;
    }

    std::cout << "[AsyncBroadcaster] Stopping..." << std::endl;

    // Signal worker to stop
    m_running.store(false);

    // Wake up worker thread
    m_queue_cv.notify_all();

    // Wait for worker to finish
    if (m_worker.joinable()) {
        m_worker.join();
    }

    // Clear any remaining tasks
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        while (!m_queue.empty()) {
            m_queue.pop();
        }
    }

    std::cout << "[AsyncBroadcaster] Stopped" << std::endl;
}

// Queue a message for broadcast (non-blocking)
bool CAsyncBroadcaster::QueueBroadcast(const CNetMessage& message,
                                       const std::vector<int>& peer_ids,
                                       Priority priority) {
    if (!m_running.load()) {
        std::cerr << "[AsyncBroadcaster] Cannot queue - not running" << std::endl;
        return false;
    }

    if (peer_ids.empty()) {
        std::cerr << "[AsyncBroadcaster] Cannot queue - no peers specified" << std::endl;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);

        // Check queue depth limit
        if (m_queue.size() >= m_max_queue_depth.load()) {
            std::cerr << "[AsyncBroadcaster] Queue full (depth: " << m_queue.size()
                      << "), dropping message" << std::endl;
            return false;
        }

        // Create broadcast task
        BroadcastTask task;
        task.message = message;
        task.peer_ids = peer_ids;
        task.priority = priority;
        task.queued_time = GetTimeMillis();
        task.retry_count = 0;

        // Add to queue
        m_queue.push(task);

        // Update statistics
        {
            std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
            m_stats.total_queued++;
            m_stats.queue_depth = m_queue.size();
        }
    }

    // Wake up worker thread
    m_queue_cv.notify_one();

    return true;
}

// Queue a block broadcast (convenience wrapper for high-priority INV)
bool CAsyncBroadcaster::BroadcastBlock(const uint256& hash, const std::vector<int>& peer_ids) {
    // Create CInv for block
    NetProtocol::CInv block_inv(NetProtocol::MSG_BLOCK_INV, hash);

    // Create INV message using message processor
    std::vector<NetProtocol::CInv> inv_vec = {block_inv};
    CNetMessage invMsg = g_message_processor->CreateInvMessage(inv_vec);

    // Queue with HIGH priority
    return QueueBroadcast(invMsg, peer_ids, PRIORITY_HIGH);
}

// Get current broadcast statistics
CAsyncBroadcaster::Stats CAsyncBroadcaster::GetStats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);

    // Calculate send rate (messages per second in last 10 seconds)
    int64_t now = GetTimeMillis();
    int64_t window_duration = now - m_stats_window_start;

    Stats current_stats = m_stats;

    if (window_duration > 0) {
        current_stats.send_rate_per_sec = (m_stats_window_sent * 1000.0) / window_duration;
    }

    return current_stats;
}

// Worker thread main loop
void CAsyncBroadcaster::WorkerThread() {
    std::cout << "[AsyncBroadcaster] Worker thread started" << std::endl;

    while (m_running.load()) {
        BroadcastTask task;

        // Wait for task or stop signal
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);

            // Wait until queue has tasks or we're stopping
            m_queue_cv.wait(lock, [this] {
                return !m_running.load() || !m_queue.empty();
            });

            // Check if stopping
            if (!m_running.load()) {
                break;
            }

            // Get next task
            if (!m_queue.empty()) {
                task = m_queue.top();
                m_queue.pop();

                // Update queue depth stat
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.queue_depth = m_queue.size();
                }
            } else {
                continue;
            }
        }

        // Process task (outside of lock)
        int64_t task_start = GetTimeMillis();
        bool success = ProcessTask(task);
        int64_t task_duration = GetTimeMillis() - task_start;

        // Update statistics
        UpdateStats(task_duration, success);

        // Handle retry if needed
        if (!success && ShouldRetry(task)) {
            // Calculate retry delay
            int64_t retry_delay = GetRetryDelay(task.retry_count);

            std::cout << "[AsyncBroadcaster] Task failed, retrying in "
                      << retry_delay << "ms (attempt "
                      << (task.retry_count + 1) << ")" << std::endl;

            // Sleep for retry delay
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay));

            // Re-queue with incremented retry count
            {
                std::lock_guard<std::mutex> lock(m_queue_mutex);
                task.retry_count++;
                m_queue.push(task);

                // Update stats
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.total_retried++;
                    m_stats.queue_depth = m_queue.size();
                }
            }

            // Wake up worker (in case it's waiting)
            m_queue_cv.notify_one();
        }
    }

    std::cout << "[AsyncBroadcaster] Worker thread stopped" << std::endl;
}

// Process a single broadcast task
bool CAsyncBroadcaster::ProcessTask(const BroadcastTask& task) {
    int success_count = 0;
    int fail_count = 0;

    // Calculate queue time
    int64_t queue_time = GetTimeMillis() - task.queued_time;

    // Get command from header (first 12 bytes, null-terminated)
    std::string cmd_str = task.message.header.GetCommand();

    std::cout << "[AsyncBroadcaster] Processing task: " << cmd_str
              << " to " << task.peer_ids.size() << " peers"
              << " (queued " << queue_time << "ms ago, priority " << task.priority << ")"
              << std::endl;

    // Send to each peer
    for (int peer_id : task.peer_ids) {
        bool sent = m_connection_manager.SendMessage(peer_id, task.message);

        if (sent) {
            success_count++;
        } else {
            fail_count++;
            std::cerr << "[AsyncBroadcaster] Failed to send to peer " << peer_id << std::endl;
        }
    }

    // Log results
    if (fail_count > 0) {
        std::cerr << "[AsyncBroadcaster] Task completed with failures: "
                  << success_count << " sent, " << fail_count << " failed" << std::endl;
    } else {
        std::cout << "[AsyncBroadcaster] Task completed successfully: "
                  << success_count << " peers" << std::endl;
    }

    // Consider success if at least one peer received the message
    return success_count > 0;
}

// Check if task should be retried
bool CAsyncBroadcaster::ShouldRetry(const BroadcastTask& task) const {
    int max_retries = m_max_retries.load();

    // Retry disabled if max_retries is 0
    if (max_retries == 0) {
        return false;
    }

    // Check if exceeded max retries
    if (task.retry_count >= max_retries) {
        std::cerr << "[AsyncBroadcaster] Max retries (" << max_retries
                  << ") exceeded, giving up" << std::endl;
        return false;
    }

    return true;
}

// Calculate retry delay with exponential backoff
int64_t CAsyncBroadcaster::GetRetryDelay(int retry_count) const {
    int base_delay = m_retry_delay_ms.load();

    // Exponential backoff: delay * (2 ^ retry_count)
    // Example with 1000ms base: 1s, 2s, 4s, 8s, 16s...
    int64_t delay = base_delay * (1 << retry_count);

    // Cap at 60 seconds
    const int64_t MAX_DELAY = 60000;
    if (delay > MAX_DELAY) {
        delay = MAX_DELAY;
    }

    return delay;
}

// Update statistics (called after each task)
void CAsyncBroadcaster::UpdateStats(int64_t task_duration_ms, bool success) {
    std::lock_guard<std::mutex> lock(m_stats_mutex);

    if (success) {
        m_stats.total_sent++;
        m_stats_window_sent++;
    } else {
        m_stats.total_failed++;
    }

    // Update average queue time (exponential moving average)
    // EMA formula: new_avg = alpha * new_value + (1 - alpha) * old_avg
    const double alpha = 0.1;  // Weight for new values (10%)
    m_stats.avg_queue_time_ms = alpha * task_duration_ms +
                                (1.0 - alpha) * m_stats.avg_queue_time_ms;

    // Reset rate calculation window every 10 seconds
    int64_t now = GetTimeMillis();
    int64_t window_duration = now - m_stats_window_start;
    const int64_t WINDOW_DURATION_MS = 10000;  // 10 seconds

    if (window_duration >= WINDOW_DURATION_MS) {
        m_stats_window_start = now;
        m_stats_window_sent = 0;
    }
}
