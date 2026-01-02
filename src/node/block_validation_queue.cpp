// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_validation_queue.h>

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <node/blockchain_storage.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/peers.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>  // IBD BOTTLENECK FIX: For CBlockTracker updates
#include <net/orphan_manager.h>  // IBD HANG FIX #23b: For orphan resolution
#include <node/block_index.h>  // For CBlockIndex
#include <primitives/block.h>  // For CBlock
#include <util/logging.h>

#include <iostream>
#include <chrono>
#include <queue>  // IBD HANG FIX #23b: For orphan queue

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

    // Start watchdog first (monitors validation thread)
    m_watchdog.Start();

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

    // Stop watchdog after worker thread is done
    m_watchdog.Stop();
}

bool CBlockValidationQueue::QueueBlock(int peer_id, const CBlock& block, int expected_height, const uint256& blockHash, CBlockIndex* pindex) {
    // Phase 2: Quick validation checks before queueing
    // IBD OPTIMIZATION: Use passed hash instead of computing RandomX

    // SSOT FIX #3: Use GetQueueDepth() instead of direct m_queue.size() access
    // This ensures atomic check with proper locking
    size_t queue_depth = GetQueueDepth();
    if (queue_depth >= MAX_QUEUE_DEPTH) {
        std::cerr << "[ValidationQueue] Queue full (" << queue_depth << " blocks), rejecting block from peer " << peer_id << std::endl;
        return false;
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

    // SSOT FIX #3: Add to queue and update stats
    // Use GetQueueDepth() after adding to get accurate count
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_queue.push(queued_block);
        m_queued_heights.insert(expected_height);  // O(1) lookup for IsHeightQueued
    }
    queue_depth = GetQueueDepth();  // SSOT FIX #3: Reuse variable, don't redeclare

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

bool CBlockValidationQueue::IsHeightQueued(int height) const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    // O(1) lookup using auxiliary set instead of O(n) queue copy
    return m_queued_heights.count(height) > 0;
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
                m_queued_heights.erase(queued_block.expected_height);  // O(1) removal for IsHeightQueued
                has_block = true;

                // SSOT FIX #3: Update queue depth in stats
                // IBD DEADLOCK FIX #11: Use m_queue.size() directly since we already hold m_queue_mutex
                // Calling GetQueueDepth() here would cause self-deadlock (tries to relock m_queue_mutex)
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.queue_depth = m_queue.size();  // Direct access - we already hold m_queue_mutex
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

    // STRESS TEST FIX: Report to watchdog that validation is starting
    // Watchdog will alert if validation takes longer than VALIDATION_TIMEOUT_SECONDS
    m_watchdog.ReportValidationStart(blockHash, expected_height);

    // STRESS TEST FIX: Wrap validation in try-catch to ensure watchdog is notified
    // on any exception. This prevents the watchdog from falsely detecting a stuck
    // validation when an exception was thrown.
    try {
        // ORPHAN BOTTLENECK FIX #2: Ensure block is saved to database
        // For orphan blocks (peer_id == -1), block should already be saved before queueing
        // For regular blocks, block is saved in block handler before queueing
        // This is a safety check - should already be saved, but verify
        if (!m_db.BlockExists(blockHash)) {
            std::cerr << "[ValidationQueue] WARNING: Block not in database, saving now (should be rare)" << std::endl;
            if (!m_db.WriteBlock(blockHash, block)) {
                std::cerr << "[ValidationQueue] ERROR: Failed to save block to database" << std::endl;
                m_watchdog.ReportValidationComplete();
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
            m_watchdog.ReportValidationComplete();
            return false;
        }

        // Calculate height and chain work
        pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
        pblockIndex->BuildChainWork();

        // Save block index to database
        if (!m_db.WriteBlockIndex(blockHash, *pblockIndex)) {
            std::cerr << "[ValidationQueue] ERROR: Failed to save block index" << std::endl;
            m_watchdog.ReportValidationComplete();
            return false;
        }

        // Add to chain state (may fail if another thread beat us - that's OK)
        if (!m_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
            // Another thread already added this block - get the existing index
            pindex = m_chainstate.GetBlockIndex(blockHash);
            if (!pindex) {
                std::cerr << "[ValidationQueue] ERROR: Block index not found after add failed" << std::endl;
                m_watchdog.ReportValidationComplete();
                return false;
            }
            // Continue with existing block index
        } else {
            pindex = m_chainstate.GetBlockIndex(blockHash);
            if (!pindex) {
                std::cerr << "[ValidationQueue] CRITICAL ERROR: Block index not found after adding!" << std::endl;
                m_watchdog.ReportValidationComplete();
                return false;
            }
        }
    }

    // Activate best chain (this is the slow operation that was blocking P2P thread)
    bool reorgOccurred = false;
    if (!m_chainstate.ActivateBestChain(pindex, block, reorgOccurred)) {
        std::cerr << "[ValidationQueue] ERROR: ActivateBestChain failed for block at height " << expected_height << std::endl;
        m_watchdog.ReportValidationComplete();
        return false;
    }

    if (reorgOccurred) {
        std::cout << "[ValidationQueue] ⚠️  CHAIN REORGANIZATION occurred at height " << expected_height << std::endl;
    }

    // DEAD CODE REMOVED: OnChunkBlockReceived and OnWindowBlockConnected
    // CBlockTracker is now the SSOT - tracking already updated via OnBlockReceived

    // Phase 2.2: Mark this block as received if it was a pending parent request
    if (g_node_context.orphan_manager) {
        g_node_context.orphan_manager->MarkParentReceived(blockHash);
    }

    // IBD HANG FIX #23b: Process orphan children after async validation completes
    // When a block validates successfully, check if any orphans were waiting for it as their parent
    // This was previously only done in the synchronous block handler path
    if (g_node_context.orphan_manager) {
        std::vector<uint256> orphanChildren = g_node_context.orphan_manager->GetOrphanChildren(blockHash);
        if (!orphanChildren.empty()) {
            std::cout << "[ValidationQueue] Found " << orphanChildren.size()
                      << " orphan children waiting for block " << blockHash.GetHex().substr(0, 16)
                      << "... at height " << expected_height << std::endl;

            // Process orphan children (queue them for validation)
            for (const uint256& orphanHash : orphanChildren) {
                CBlock orphanBlock;
                if (g_node_context.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                    uint256 orphanBlockHash = orphanBlock.GetHash();

                    // Verify parent is now available
                    CBlockIndex* pOrphanParent = m_chainstate.GetBlockIndex(orphanBlock.hashPrevBlock);
                    if (!pOrphanParent) {
                        // Parent still not available - keep orphan for later
                        std::cout << "[ValidationQueue] Orphan " << orphanBlockHash.GetHex().substr(0, 16)
                                  << "... parent still not available, keeping in pool" << std::endl;
                        continue;
                    }

                    int orphanHeight = pOrphanParent->nHeight + 1;

                    // Check if already being processed (by IBD coordinator or another thread)
                    if (m_chainstate.GetBlockIndex(orphanBlockHash)) {
                        // Block index exists - another thread is handling it
                        g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                        continue;
                    }

                    // Create block index for orphan
                    auto pOrphanIndex = std::make_unique<CBlockIndex>(orphanBlock);
                    pOrphanIndex->phashBlock = orphanBlockHash;
                    pOrphanIndex->nStatus = CBlockIndex::BLOCK_HAVE_DATA;
                    pOrphanIndex->pprev = pOrphanParent;
                    pOrphanIndex->nHeight = orphanHeight;
                    pOrphanIndex->BuildChainWork();

                    // Save block to database
                    if (!m_db.WriteBlock(orphanBlockHash, orphanBlock)) {
                        std::cerr << "[ValidationQueue] Failed to save orphan block to database" << std::endl;
                        continue;
                    }

                    // Add to chain state (may fail if another thread beat us - that's OK)
                    CBlockIndex* pOrphanIndexRaw = pOrphanIndex.get();
                    if (!m_chainstate.AddBlockIndex(orphanBlockHash, std::move(pOrphanIndex))) {
                        // Another thread already added this orphan - just erase from pool
                        g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                        continue;
                    }

                    // Save block index to database
                    if (!m_db.WriteBlockIndex(orphanBlockHash, *pOrphanIndexRaw)) {
                        std::cerr << "[ValidationQueue] Failed to save orphan block index" << std::endl;
                        continue;
                    }

                    // Queue orphan for async validation
                    // IBD OPTIMIZATION: Pass orphanBlockHash to avoid RandomX recomputation
                    if (QueueBlock(-1, orphanBlock, orphanHeight, orphanBlockHash, pOrphanIndexRaw)) {
                        std::cout << "[ValidationQueue] Queued orphan " << orphanBlockHash.GetHex().substr(0, 16)
                                  << "... at height " << orphanHeight << " for validation" << std::endl;
                        // Successfully queued - now safe to remove from orphan pool
                        g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                    } else {
                        std::cerr << "[ValidationQueue] Failed to queue orphan for validation, keeping in pool" << std::endl;
                    }
                }
            }
        }
    }

    std::cout << "[ValidationQueue] Successfully validated block at height " << expected_height << std::endl;
    m_watchdog.ReportValidationComplete();
    return true;

    } catch (const std::exception& e) {
        // STRESS TEST FIX: Catch and log all exceptions to prevent frozen validation
        std::cerr << "[ValidationQueue] EXCEPTION validating block " << blockHash.GetHex().substr(0, 16)
                  << "... at height " << expected_height << ": " << e.what() << std::endl;
        m_watchdog.ReportValidationComplete();
        return false;

    } catch (...) {
        // STRESS TEST FIX: Catch unknown exceptions
        std::cerr << "[ValidationQueue] UNKNOWN EXCEPTION validating block " << blockHash.GetHex().substr(0, 16)
                  << "... at height " << expected_height << std::endl;
        m_watchdog.ReportValidationComplete();
        return false;
    }
}

void CBlockValidationQueue::NotifyBlockValidated(const uint256& hash, bool success) {
    std::lock_guard<std::mutex> lock(m_notify_mutex);
    auto it = m_pending_notifications.find(hash);
    if (it != m_pending_notifications.end()) {
        it->second.set_value(success);
    }
}

