// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/message_queue.h>
#include <net/net.h>
#include <iostream>
#include <chrono>

// Global message queue instance
std::atomic<CMessageProcessorQueue*> g_message_queue{nullptr};

// Helper function to get current time in milliseconds
static int64_t GetTimeMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// Constructor
CMessageProcessorQueue::CMessageProcessorQueue(CNetMessageProcessor& msg_proc,
                                               size_t num_workers)
    : m_message_processor(msg_proc)
    , m_num_workers(num_workers > 0 ? num_workers : 1) {
}

// Destructor
CMessageProcessorQueue::~CMessageProcessorQueue() {
    Stop();
}

// Start worker threads
bool CMessageProcessorQueue::Start() {
    if (m_running.load()) {
        std::cerr << "[MessageQueue] Already running" << std::endl;
        return false;
    }

    m_running.store(true);

    // Initialize stats
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats_window_start = GetTimeMillis();
        m_stats_window_processed = 0;
    }

    // Launch worker threads
    try {
        for (size_t i = 0; i < m_num_workers; i++) {
            m_workers.emplace_back(&CMessageProcessorQueue::WorkerThread, this);
        }
        std::cout << "[MessageQueue] Started " << m_num_workers
                  << " worker thread(s)" << std::endl;
        return true;
    } catch (const std::exception& e) {
        m_running.store(false);
        std::cerr << "[MessageQueue] Failed to start workers: " << e.what() << std::endl;
        return false;
    }
}

// Stop worker threads
void CMessageProcessorQueue::Stop() {
    if (!m_running.load()) {
        return;
    }

    std::cout << "[MessageQueue] Stopping..." << std::endl;

    // Signal workers to stop
    m_running.store(false);

    // Wake up all workers
    m_queue_cv.notify_all();

    // Wait for workers to finish
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    m_workers.clear();

    // Clear remaining queue
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        while (!m_queue.empty()) {
            m_queue.pop();
        }
    }

    std::cout << "[MessageQueue] Stopped" << std::endl;
}

// Enqueue message for async processing
bool CMessageProcessorQueue::EnqueueMessage(int peer_id, const CNetMessage& message,
                                            Priority priority) {
    if (!m_running.load()) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);

        // Check queue depth limit
        if (m_queue.size() >= m_max_queue_depth.load()) {
            std::cerr << "[MessageQueue] Queue full (" << m_queue.size()
                      << "), dropping message from peer " << peer_id << std::endl;

            std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
            m_stats.total_dropped++;
            return false;
        }

        // Create queued message
        QueuedMessage msg;
        msg.peer_id = peer_id;
        msg.message = message;
        msg.priority = priority;
        msg.queued_time = GetTimeMillis();

        // Add to queue
        m_queue.push(msg);

        // Update stats
        {
            std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
            m_stats.total_queued++;
            m_stats.queue_depth = m_queue.size();
        }
    }

    // Wake up a worker
    m_queue_cv.notify_one();

    return true;
}

// Determine priority based on message command
CMessageProcessorQueue::Priority
CMessageProcessorQueue::GetMessagePriority(const CNetMessage& message) {
    std::string cmd = message.header.GetCommand();

    if (cmd == "block") {
        return PRIORITY_CRITICAL;
    } else if (cmd == "headers") {
        return PRIORITY_HIGH;
    } else if (cmd == "tx" || cmd == "inv" || cmd == "getdata") {
        return PRIORITY_NORMAL;
    } else {
        return PRIORITY_LOW;
    }
}

// Get current statistics
CMessageProcessorQueue::Stats CMessageProcessorQueue::GetStats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);

    // Calculate processing rate
    int64_t now = GetTimeMillis();
    int64_t window_duration = now - m_stats_window_start;

    Stats current_stats = m_stats;

    if (window_duration > 0) {
        current_stats.process_rate_per_sec =
            (m_stats_window_processed * 1000.0) / window_duration;
    }

    return current_stats;
}

// Worker thread main loop
void CMessageProcessorQueue::WorkerThread() {
    std::cout << "[MessageQueue] Worker thread started" << std::endl;

    while (m_running.load()) {
        QueuedMessage msg;

        // Wait for message or stop signal
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);

            m_queue_cv.wait(lock, [this] {
                return !m_running.load() || !m_queue.empty();
            });

            // Check if stopping
            if (!m_running.load()) {
                break;
            }

            // Get next message
            if (!m_queue.empty()) {
                msg = m_queue.top();
                m_queue.pop();

                // Update queue depth
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.queue_depth = m_queue.size();
                }
            } else {
                continue;
            }
        }

        // Process message (outside of lock - this is the key!)
        int64_t queue_time = GetTimeMillis() - msg.queued_time;
        bool success = ProcessQueuedMessage(msg);

        // Update statistics
        UpdateStats(queue_time, success);
    }

    std::cout << "[MessageQueue] Worker thread stopped" << std::endl;
}

// Process a single message
bool CMessageProcessorQueue::ProcessQueuedMessage(const QueuedMessage& msg) {
    try {
        // This is the expensive operation that now runs in background thread
        return m_message_processor.ProcessMessage(msg.peer_id, msg.message);
    } catch (const std::exception& e) {
        std::cerr << "[MessageQueue] Exception processing message from peer "
                  << msg.peer_id << ": " << e.what() << std::endl;
        return false;
    }
}

// Update statistics
void CMessageProcessorQueue::UpdateStats(int64_t queue_time_ms, bool success) {
    std::lock_guard<std::mutex> lock(m_stats_mutex);

    if (success) {
        m_stats.total_processed++;
        m_stats_window_processed++;
    }

    // Update average queue time (exponential moving average)
    const double alpha = 0.1;
    m_stats.avg_queue_time_ms = alpha * queue_time_ms +
                                (1.0 - alpha) * m_stats.avg_queue_time_ms;

    // Reset rate calculation window every 10 seconds
    int64_t now = GetTimeMillis();
    int64_t window_duration = now - m_stats_window_start;
    const int64_t WINDOW_DURATION_MS = 10000;

    if (window_duration >= WINDOW_DURATION_MS) {
        m_stats_window_start = now;
        m_stats_window_processed = 0;
    }
}
