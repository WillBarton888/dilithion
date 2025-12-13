// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_validation_queue.h>

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <core/blockchain_storage.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/peers.h>
#include <net/block_fetcher.h>
#include <node/block_index.h>  // For CBlockIndex
#include <primitives/block.h>  // For CBlock
#include <util/logging.h>

#include <iostream>
#include <chrono>

extern NodeContext g_node_context;

CBlockValidationQueue::CBlockValidationQueue(CChainState& chainstate, CBlockchainDB& db)
    : m_chainstate(chainstate), m_db(db) {}

CBlockValidationQueue::~CBlockValidationQueue() {
    Stop();
}

bool CBlockValidationQueue::Start() {
    if (m_running.load()) {
        return false;  // Already running
    }

    m_running.store(true);
    m_worker = std::thread(&CBlockValidationQueue::ValidationWorker, this);
    return true;
}

void CBlockValidationQueue::Stop() {
    if (!m_running.load()) {
        return;  // Already stopped
    }

    m_running.store(false);
    m_queue_cv.notify_all();  // Wake worker to check m_running

    if (m_worker.joinable()) {
        m_worker.join();
    }
}

bool CBlockValidationQueue::QueueBlock(int peer_id, const CBlock& block, int expected_height, CBlockIndex* pindex) {
    // Phase 2: Quick validation checks before queueing
    uint256 blockHash = block.GetHash();

    // Check if queue is full (backpressure)
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        if (m_queue.size() >= MAX_QUEUE_DEPTH) {
            std::cerr << "[ValidationQueue] Queue full (" << m_queue.size() << " blocks), rejecting block from peer " << peer_id << std::endl;
            return false;
        }
    }

    // Basic PoW check (cheap, can do in P2P thread)
    // Skip PoW check for checkpointed blocks (same as current code)
    int currentChainHeight = m_chainstate.GetHeight();
    int checkpointHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;
    bool skipPoWCheck = (checkpointHeight > 0 && currentChainHeight < checkpointHeight);

    if (!skipPoWCheck && !CheckProofOfWork(blockHash, block.nBits)) {
        std::cerr << "[ValidationQueue] Block from peer " << peer_id << " has invalid PoW, rejecting" << std::endl;
        if (g_node_context.peer_manager) {
            g_node_context.peer_manager->Misbehaving(peer_id, 10);
        }
        return false;
    }

    // Check if we already have this block
    CBlockIndex* existing = m_chainstate.GetBlockIndex(blockHash);
    if (existing && existing->HaveData() && (existing->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
        std::cout << "[ValidationQueue] Block already in chain, skipping" << std::endl;
        return false;  // Already processed
    }

    // Create queued block entry
    QueuedBlock queued_block;
    queued_block.block = block;
    queued_block.peer_id = peer_id;
    queued_block.hash = blockHash;
    queued_block.expected_height = expected_height;
    queued_block.queued_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    queued_block.pindex = pindex ? pindex : existing;

    // Add to queue and update stats
    size_t queue_depth;
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_queue.push(queued_block);
        queue_depth = m_queue.size();
    }

    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats.total_queued++;
        m_stats.queue_depth = queue_depth;
    }

    // Wake worker thread
    m_queue_cv.notify_one();

    std::cout << "[ValidationQueue] Queued block " << blockHash.GetHex().substr(0, 16)
              << "... at height " << expected_height << " (queue depth: " << queue_depth << ")" << std::endl;

    return true;
}

bool CBlockValidationQueue::WaitForBlock(const uint256& hash, std::chrono::milliseconds timeout) {
    std::promise<bool> promise;
    auto future = promise.get_future();

    {
        std::lock_guard<std::mutex> lock(m_notify_mutex);
        m_pending_notifications[hash] = std::move(promise);
    }

    // Wait for validation to complete
    auto status = future.wait_for(timeout);
    if (status == std::future_status::timeout) {
        std::lock_guard<std::mutex> lock(m_notify_mutex);
        m_pending_notifications.erase(hash);
        return false;
    }

    bool result = future.get();

    {
        std::lock_guard<std::mutex> lock(m_notify_mutex);
        m_pending_notifications.erase(hash);
    }

    return result;
}

CBlockValidationQueue::Stats CBlockValidationQueue::GetStats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    std::lock_guard<std::mutex> queue_lock(m_queue_mutex);
    m_stats.queue_depth = m_queue.size();
    return m_stats;
}

size_t CBlockValidationQueue::GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    return m_queue.size();
}

void CBlockValidationQueue::ValidationWorker() {
    std::cout << "[ValidationQueue] Worker thread started" << std::endl;

    while (m_running.load()) {
        QueuedBlock queued_block;
        bool has_block = false;

        // Wait for blocks in queue
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(lock, [this] {
                return !m_queue.empty() || !m_running.load();
            });

            if (!m_running.load() && m_queue.empty()) {
                break;  // Shutting down
            }

            if (!m_queue.empty()) {
                queued_block = m_queue.top();
                m_queue.pop();
                has_block = true;

                // Update queue depth in stats
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.queue_depth = m_queue.size();
                }
            }
        }

        if (!has_block) {
            continue;
        }

        // Process the block
        auto start_time = std::chrono::steady_clock::now();
        bool success = ProcessBlock(queued_block);
        auto end_time = std::chrono::steady_clock::now();
        auto validation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

        // Update stats
        {
            std::lock_guard<std::mutex> lock(m_stats_mutex);
            if (success) {
                m_stats.total_validated++;
                m_stats.last_validated_height = queued_block.expected_height;
            } else {
                m_stats.total_rejected++;
            }

            // Update average validation time (exponential moving average)
            if (m_stats.total_validated > 0) {
                m_stats.avg_validation_time_ms = 
                    (m_stats.avg_validation_time_ms * 7 + validation_time) / 8.0;
            }

            m_stats.last_validation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }

        // Notify waiting threads
        NotifyBlockValidated(queued_block.hash, success);

        // Update last validated height
        if (success) {
            m_last_validated_height.store(queued_block.expected_height);
        }
    }

    std::cout << "[ValidationQueue] Worker thread stopped" << std::endl;
}

bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_block) {
    const CBlock& block = queued_block.block;
    const uint256& blockHash = queued_block.hash;
    int peer_id = queued_block.peer_id;
    int expected_height = queued_block.expected_height;

    std::cout << "[ValidationQueue] Processing block " << blockHash.GetHex().substr(0, 16)
              << "... at height " << expected_height << std::endl;

    // Ensure block is saved to database (should already be done, but double-check)
    if (!m_db.BlockExists(blockHash)) {
        if (!m_db.WriteBlock(blockHash, block)) {
            std::cerr << "[ValidationQueue] ERROR: Failed to save block to database" << std::endl;
            return false;
        }
    }

    // Get or create block index
    CBlockIndex* pindex = queued_block.pindex;
    if (!pindex) {
        pindex = m_chainstate.GetBlockIndex(blockHash);
    }

    if (!pindex) {
        // Create block index
        auto pblockIndex = std::make_unique<CBlockIndex>(block);
        pblockIndex->phashBlock = blockHash;
        pblockIndex->nStatus = CBlockIndex::BLOCK_HAVE_DATA;

        // Link to parent
        pblockIndex->pprev = m_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (!pblockIndex->pprev) {
            std::cerr << "[ValidationQueue] ERROR: Parent block not found for block at height " << expected_height << std::endl;
            return false;
        }

        // Calculate height and chain work
        pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
        pblockIndex->BuildChainWork();

        // Save block index to database
        if (!m_db.WriteBlockIndex(blockHash, *pblockIndex)) {
            std::cerr << "[ValidationQueue] ERROR: Failed to save block index" << std::endl;
            return false;
        }

        // Add to chain state
        if (!m_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
            std::cerr << "[ValidationQueue] ERROR: Failed to add block to chain state" << std::endl;
            return false;
        }

        pindex = m_chainstate.GetBlockIndex(blockHash);
        if (!pindex) {
            std::cerr << "[ValidationQueue] CRITICAL ERROR: Block index not found after adding!" << std::endl;
            return false;
        }
    }

    // Activate best chain (this is the slow operation that was blocking P2P thread)
    bool reorgOccurred = false;
    if (!m_chainstate.ActivateBestChain(pindex, block, reorgOccurred)) {
        std::cerr << "[ValidationQueue] ERROR: ActivateBestChain failed for block at height " << expected_height << std::endl;
        return false;
    }

    if (reorgOccurred) {
        std::cout << "[ValidationQueue] ⚠️  CHAIN REORGANIZATION occurred at height " << expected_height << std::endl;
    }

    // IBD BOTTLENECK FIX #10: Mark block as received after successful validation
    // This ensures correct sequence: receive → validate → connect → update window
    // Previously MarkBlockReceived() was called before validation, causing sequence issues
    if (g_node_context.block_fetcher) {
        g_node_context.block_fetcher->MarkBlockReceived(peer_id, blockHash);
    }

    // IBD BOTTLENECK FIX #2: Update window state for ALL validated blocks, not just new tip
    // Previously only updated window when block became new tip, causing window to stall
    // Now updates window for all successfully validated blocks, allowing continuous advancement
    if (g_node_context.block_fetcher) {
        g_node_context.block_fetcher->OnWindowBlockConnected(pindex->nHeight);
    }

    std::cout << "[ValidationQueue] Successfully validated block at height " << expected_height << std::endl;
    return true;
}

void CBlockValidationQueue::NotifyBlockValidated(const uint256& hash, bool success) {
    std::lock_guard<std::mutex> lock(m_notify_mutex);
    auto it = m_pending_notifications.find(hash);
    if (it != m_pending_notifications.end()) {
        it->second.set_value(success);
    }
}

