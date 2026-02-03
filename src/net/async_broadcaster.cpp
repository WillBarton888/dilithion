// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/async_broadcaster.h>
#include <net/net.h>
#include <net/node.h>     // BIP 130: For CNode::fPreferHeaders
#include <net/connman.h>  // Phase 5: CConnman
#include <net/protocol.h>
#include <util/logging.h>  // For g_verbose flag
#include <iostream>
#include <chrono>

// Helper function to get current time in milliseconds
static int64_t GetTimeMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// g_message_processor is now declared as std::atomic in net.h (P0-5 FIX)

// Constructor
CAsyncBroadcaster::CAsyncBroadcaster(CConnman* connman)
    : m_connman(connman) {
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
    auto* msg_processor = g_message_processor.load();
    if (!msg_processor) return false;
    CNetMessage invMsg = msg_processor->CreateInvMessage(inv_vec);

    // Queue with HIGH priority
    return QueueBroadcast(invMsg, peer_ids, PRIORITY_HIGH);
}

// BIP 130: Queue a block broadcast with HEADERS vs INV routing by peer preference
bool CAsyncBroadcaster::BroadcastBlock(const uint256& hash, const CBlockHeader& header, const std::vector<int>& peer_ids) {
    if (!m_connman) {
        std::cerr << "[AsyncBroadcaster] No connection manager for BIP 130 routing" << std::endl;
        return false;
    }

    auto* msg_processor = g_message_processor.load();
    if (!msg_processor) {
        std::cerr << "[AsyncBroadcaster] No message processor for BIP 130 routing" << std::endl;
        return false;
    }

    // Partition peers by their sendheaders preference
    std::vector<int> headers_peers;  // Peers who want HEADERS (fPreferHeaders = true)
    std::vector<int> inv_peers;      // Peers who want INV (fPreferHeaders = false)

    for (int peer_id : peer_ids) {
        CNode* pnode = m_connman->GetNode(peer_id);
        if (pnode && !pnode->fDisconnect.load()) {
            if (pnode->fPreferHeaders.load()) {
                headers_peers.push_back(peer_id);
            } else {
                inv_peers.push_back(peer_id);
            }
        }
    }

    bool success = true;

    // Send HEADERS to peers who prefer it (BIP 130)
    if (!headers_peers.empty()) {
        std::vector<CBlockHeader> headers_vec = {header};
        CNetMessage headersMsg = msg_processor->CreateHeadersMessage(headers_vec);

        if (!QueueBroadcast(headersMsg, headers_peers, PRIORITY_HIGH)) {
            std::cerr << "[AsyncBroadcaster] Failed to queue HEADERS broadcast" << std::endl;
            success = false;
        } else {
            std::cout << "[BIP130] Sending HEADERS to " << headers_peers.size() << " peer(s)" << std::endl;
        }
    }

    // Send INV to peers who don't prefer HEADERS
    if (!inv_peers.empty()) {
        NetProtocol::CInv block_inv(NetProtocol::MSG_BLOCK_INV, hash);
        std::vector<NetProtocol::CInv> inv_vec = {block_inv};
        CNetMessage invMsg = msg_processor->CreateInvMessage(inv_vec);

        if (!QueueBroadcast(invMsg, inv_peers, PRIORITY_HIGH)) {
            std::cerr << "[AsyncBroadcaster] Failed to queue INV broadcast" << std::endl;
            success = false;
        } else {
            std::cout << "[BIP130] Sending INV to " << inv_peers.size() << " peer(s)" << std::endl;
        }
    }

    return success;
}

// BIP 152: Queue a block broadcast with compact blocks to high-bandwidth peers
bool CAsyncBroadcaster::BroadcastBlock(const uint256& hash, const CBlock& block, const std::vector<int>& peer_ids) {
    if (!m_connman) {
        std::cerr << "[AsyncBroadcaster] No connection manager for BIP 152 routing" << std::endl;
        return false;
    }

    auto* msg_processor = g_message_processor.load();
    if (!msg_processor) {
        std::cerr << "[AsyncBroadcaster] No message processor for BIP 152 routing" << std::endl;
        return false;
    }

    // Partition peers by their preferences:
    // 1. High-bandwidth compact block peers (fHighBandwidth = true) → CMPCTBLOCK
    // 2. Headers-preferring peers (fPreferHeaders = true) → HEADERS
    // 3. Other peers → INV
    std::vector<int> cmpctblock_peers;  // Peers who want CMPCTBLOCK (BIP 152 high-bandwidth)
    std::vector<int> headers_peers;      // Peers who want HEADERS (BIP 130)
    std::vector<int> inv_peers;          // Peers who want INV

    for (int peer_id : peer_ids) {
        CNode* pnode = m_connman->GetNode(peer_id);
        if (pnode && !pnode->fDisconnect.load()) {
            if (pnode->fSupportsCompactBlocks.load() && pnode->fHighBandwidth.load()) {
                cmpctblock_peers.push_back(peer_id);
            } else if (pnode->fPreferHeaders.load() || pnode->fSupportsCompactBlocks.load()) {
                headers_peers.push_back(peer_id);
            } else {
                inv_peers.push_back(peer_id);
            }
        }
    }

    // Diagnostic: log peer routing breakdown (rate-limited to avoid spam)
    static int relay_log_count = 0;
    int null_nodes = 0;
    int disconnecting = 0;
    int supports_cmpct = 0;
    int high_bw = 0;
    for (int pid : peer_ids) {
        CNode* pn = m_connman->GetNode(pid);
        if (!pn) { null_nodes++; continue; }
        if (pn->fDisconnect.load()) { disconnecting++; continue; }
        if (pn->fSupportsCompactBlocks.load()) supports_cmpct++;
        if (pn->fHighBandwidth.load()) high_bw++;
    }
    if (relay_log_count++ < 20 || relay_log_count % 100 == 0) {
        std::cout << "[BIP152-DIAG] Block relay routing: total=" << peer_ids.size()
                  << " cmpctblock=" << cmpctblock_peers.size()
                  << " headers=" << headers_peers.size()
                  << " inv=" << inv_peers.size()
                  << " null_node=" << null_nodes
                  << " disconnecting=" << disconnecting
                  << " supports_cmpct=" << supports_cmpct
                  << " high_bw=" << high_bw << std::endl;
    }

    bool success = true;

    // Send CMPCTBLOCK to high-bandwidth compact block peers (BIP 152)
    if (!cmpctblock_peers.empty()) {
        // Create compact block from full block
        CBlockHeaderAndShortTxIDs cmpctblock(block);
        CNetMessage cmpctblockMsg = msg_processor->CreateCmpctBlockMessage(cmpctblock);

        if (!QueueBroadcast(cmpctblockMsg, cmpctblock_peers, PRIORITY_HIGH)) {
            std::cerr << "[AsyncBroadcaster] Failed to queue CMPCTBLOCK broadcast" << std::endl;
            success = false;
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BIP152] Sending CMPCTBLOCK to " << cmpctblock_peers.size() << " high-bandwidth peer(s) "
                          << "(shorttxids=" << cmpctblock.shorttxids.size() << ", prefilled=" << cmpctblock.prefilledtxn.size() << ")" << std::endl;
        }
    }

    // Send HEADERS to peers who prefer it (BIP 130)
    if (!headers_peers.empty()) {
        std::vector<CBlockHeader> headers_vec = {block};  // CBlock inherits from CBlockHeader
        CNetMessage headersMsg = msg_processor->CreateHeadersMessage(headers_vec);

        if (!QueueBroadcast(headersMsg, headers_peers, PRIORITY_HIGH)) {
            std::cerr << "[AsyncBroadcaster] Failed to queue HEADERS broadcast" << std::endl;
            success = false;
        } else {
            std::cout << "[BIP130] Sending HEADERS to " << headers_peers.size() << " peer(s)" << std::endl;
        }
    }

    // Send INV to remaining peers
    if (!inv_peers.empty()) {
        NetProtocol::CInv block_inv(NetProtocol::MSG_BLOCK_INV, hash);
        std::vector<NetProtocol::CInv> inv_vec = {block_inv};
        CNetMessage invMsg = msg_processor->CreateInvMessage(inv_vec);

        if (!QueueBroadcast(invMsg, inv_peers, PRIORITY_HIGH)) {
            std::cerr << "[AsyncBroadcaster] Failed to queue INV broadcast" << std::endl;
            success = false;
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BIP152] Sending INV to " << inv_peers.size() << " peer(s)" << std::endl;
        }
    }

    return success;
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

}

// Process a single broadcast task
bool CAsyncBroadcaster::ProcessTask(const BroadcastTask& task) {
    int success_count = 0;
    int fail_count = 0;

    // Calculate queue time
    int64_t queue_time = GetTimeMillis() - task.queued_time;

    // Get command from header (first 12 bytes, null-terminated)
    std::string cmd_str = task.message.header.GetCommand();


    // Send to each peer
    if (!m_connman) {
        std::cerr << "[AsyncBroadcaster] No connection manager available" << std::endl;
        return false;
    }

    for (int peer_id : task.peer_ids) {
        // Phase 5: Use CConnman::PushMessage instead of SendMessage
        // PushMessage doesn't return a bool, so we check if node exists
        CNode* pnode = m_connman->GetNode(peer_id);
        if (pnode && !pnode->fDisconnect.load()) {
            m_connman->PushMessage(peer_id, task.message);
            success_count++;
        } else {
            fail_count++;
            std::cerr << "[AsyncBroadcaster] Failed to send to peer " << peer_id 
                      << " (node not found or disconnected)" << std::endl;
        }
    }

    // Log results
    if (fail_count > 0) {
        std::cerr << "[AsyncBroadcaster] Task completed with failures: "
                  << success_count << " sent, " << fail_count << " failed" << std::endl;
    } else {
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
    // CID 1675228 FIX: Cast to int64_t before arithmetic to prevent integer overflow
    // The expression (1 << retry_count) is evaluated as int, which can overflow if retry_count is large.
    // Casting to int64_t before shifting ensures the operation happens in a wider type.
    int64_t base_delay = static_cast<int64_t>(m_retry_delay_ms.load());

    // Exponential backoff: delay * (2 ^ retry_count)
    // Example with 1000ms base: 1s, 2s, 4s, 8s, 16s...
    // Cast 1 to int64_t before shifting to prevent overflow in narrow int type
    int64_t delay = base_delay * (static_cast<int64_t>(1) << retry_count);

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
