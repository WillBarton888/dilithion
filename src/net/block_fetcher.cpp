// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/block_fetcher.h>
#include <net/peers.h>
#include <net/block_tracker.h>
#include <core/node_context.h>
#include <node/block_validation_queue.h>
#include <consensus/chain.h>
#include <algorithm>
#include <sstream>
#include <set>  // BUG #165 FIX: For std::set in CleanupUnsuitablePeers

// Forward declaration
extern NodeContext g_node_context;

/**
 * @file block_fetcher.cpp
 * @brief Implementation of parallel block downloading for IBD
 *
 * Implements Bitcoin Core's parallel block download strategy with intelligent
 * peer selection, timeout handling, and priority-based fetching.
 */

CBlockFetcher::CBlockFetcher(CPeerManager* peer_manager)
    : m_peer_manager(peer_manager), nBlocksReceivedTotal(0)
{
    lastBlockReceived = std::chrono::steady_clock::now();
}

void CBlockFetcher::QueueBlockForDownload(const uint256& hash, int height,
                                          NodeId announcing_peer, bool highPriority)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Don't queue if already in-flight or already queued
    if (mapBlocksInFlight.count(hash) > 0) {
        return;
    }

    if (setQueuedHashes.count(hash) > 0) {
        return;
    }

    // Add to priority queue
    queueBlocksToFetch.push(BlockDownloadRequest(hash, height, announcing_peer, highPriority));
    setQueuedHashes.insert(hash);

    // BUG #64: Track which peer announced this block for preferred download
    if (announcing_peer != -1) {
        mapPreferredPeers[hash] = announcing_peer;
    }

}

NodeId CBlockFetcher::GetPreferredPeer(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto it = mapPreferredPeers.find(hash);
    if (it != mapPreferredPeers.end()) {
        return it->second;
    }
    return -1;
}

bool CBlockFetcher::RequestBlock(NodeId peer, const uint256& hash, int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: Delegate to CBlockTracker via RequestBlockFromPeer
    // This method is legacy - new code should use RequestBlockFromPeer directly
    if (g_node_context.block_tracker) {
        // Check if already tracked
        if (g_node_context.block_tracker->IsTracked(height)) {
            return false;
        }
        // AddBlock handles capacity checks
        return g_node_context.block_tracker->AddBlock(height, hash, peer);
    }

    // Fallback for when block_tracker not available
    if (!m_peer_manager) {
        return false;
    }

    auto peer_obj = m_peer_manager->GetPeer(peer);
    if (!peer_obj) {
        return false;
    }

    int blocks_in_flight = m_peer_manager->GetBlocksInFlightForPeer(peer);
    if (blocks_in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    return true;
}

bool CBlockFetcher::MarkBlockReceived(NodeId peer, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking - just delegate to it
    int height = -1;
    if (g_node_context.block_tracker) {
        height = g_node_context.block_tracker->OnBlockReceived(hash);
    }

    // Update stats
    nBlocksReceivedTotal++;
    lastBlockReceived = std::chrono::steady_clock::now();

    // Notify CPeerManager for peer stats (downloads count, etc.)
    if (m_peer_manager) {
        m_peer_manager->MarkBlockAsReceived(peer, hash);
    }

    return (height > 0);
}

std::vector<std::pair<uint256, int>> CBlockFetcher::GetNextBlocksToFetch(int maxBlocks)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<std::pair<uint256, int>> result;

    int availableSlots = GetAvailableSlots();
    int blocksToFetch = std::min(availableSlots, maxBlocks);

    if (blocksToFetch <= 0) {
        return result;
    }

    // Temporary queue to rebuild priority queue after extraction
    std::priority_queue<BlockDownloadRequest> tempQueue;

    // Extract blocks from priority queue
    while (!queueBlocksToFetch.empty() && result.size() < static_cast<size_t>(blocksToFetch)) {
        BlockDownloadRequest req = queueBlocksToFetch.top();
        queueBlocksToFetch.pop();

        // Skip if already in-flight (shouldn't happen, but safety check)
        if (mapBlocksInFlight.count(req.hash) > 0) {
            continue;
        }

        result.push_back(std::make_pair(req.hash, req.nHeight));

        // Don't add back to temp queue (it's being fetched now)
        setQueuedHashes.erase(req.hash);
    }

    // Rebuild queue with remaining items
    while (!queueBlocksToFetch.empty()) {
        tempQueue.push(queueBlocksToFetch.top());
        queueBlocksToFetch.pop();
    }
    queueBlocksToFetch = tempQueue;

    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

std::vector<uint256> CBlockFetcher::CheckTimeouts()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<uint256> timedOut;
    auto now = std::chrono::steady_clock::now();

    for (const auto& entry : mapBlocksInFlight) {
        auto timeSinceRequest = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.second.timeRequested
        );

        if (timeSinceRequest >= BLOCK_DOWNLOAD_TIMEOUT) {
            timedOut.push_back(entry.first);
        }
    }

    return timedOut;
}

void CBlockFetcher::RetryTimedOutBlocks(const std::vector<uint256>& timedOutHashes)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    for (const uint256& hash : timedOutHashes) {
        auto it = mapBlocksInFlight.find(hash);
        if (it == mapBlocksInFlight.end()) {
            continue;  // Already removed
        }

        CBlockInFlight& inFlight = it->second;
        NodeId stalledPeer = inFlight.peer;
        int height = inFlight.nHeight;
        int retries = inFlight.nRetries;

        // Phase 1: Mark peer as stalled via CPeerManager
        if (m_peer_manager) {
            m_peer_manager->UpdatePeerStats(stalledPeer, false, std::chrono::milliseconds(0));
        }

        // Remove from local in-flight tracking
        mapBlocksInFlight.erase(it);

        // Update peer's block set
        if (mapPeerBlocks.count(stalledPeer) > 0) {
            mapPeerBlocks[stalledPeer].erase(hash);
            if (mapPeerBlocks[stalledPeer].empty()) {
                mapPeerBlocks.erase(stalledPeer);
            }
        }

        // Phase 1: Notify CPeerManager of block removal
        if (m_peer_manager) {
            m_peer_manager->RemoveBlockFromFlight(hash);
        }

        // Re-queue if not exceeded max retries
        if (retries < MAX_RETRIES) {
            // Re-queue with high priority and incremented retry count
            queueBlocksToFetch.push(BlockDownloadRequest(hash, height, -1, true));  // High priority for retries
            setQueuedHashes.insert(hash);
        } else {
            std::cerr << "[BlockFetcher] Block exceeded max retries, dropping: "
                      << hash.GetHex().substr(0, 16) << "..." << std::endl;
        }
    }
}

NodeId CBlockFetcher::SelectPeerForDownload(const uint256& hash, NodeId preferred_peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Phase 1: CPeerManager is single source of truth for peer selection
    if (!m_peer_manager) {
        return -1;  // Cannot operate without peer manager
    }

    // Try the preferred peer first (the one that announced the block)
    if (preferred_peer != -1 && m_peer_manager->IsPeerSuitableForDownload(preferred_peer)) {
        // IBD STUCK FIX #9: Use GetBlocksInFlightForPeer() instead of stale counter
        int peer_in_flight = m_peer_manager->GetBlocksInFlightForPeer(preferred_peer);
        if (peer_in_flight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            return preferred_peer;
        }
    }

    // Get all valid peers from CPeerManager
    std::vector<int> valid_peers = m_peer_manager->GetValidPeersForDownload();

    NodeId bestPeer = -1;
    NodeId fallbackPeer = -1;
    int bestScore = -1;

    for (int peer_id : valid_peers) {
        auto peer = m_peer_manager->GetPeer(peer_id);
        if (!peer) {
            continue;
        }

        // IBD STUCK FIX #9: Must have capacity (use SSOT not stale counter)
        int in_flight = m_peer_manager->GetBlocksInFlightForPeer(peer_id);
        if (in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            continue;
        }

        // Check if suitable (uses CPeer::IsSuitableForDownload)
        bool suitable = peer->IsSuitableForDownload();
        if (!suitable) {
            if (fallbackPeer == -1) {
                fallbackPeer = peer_id;
            }
            continue;
        }

        // Calculate score (higher is better)
        int score = 1000;

        // Preferred peers get bonus
        if (peer->fPreferredDownload) {
            score += 500;
        }

        // Penalize for stalls
        score -= peer->nStallingCount * 100;

        // Bonus for fast response time (inverse of time in ms)
        if (peer->avgResponseTime.count() > 0) {
            score += 1000 / (peer->avgResponseTime.count() / 100 + 1);
        }

        // Bonus for successful downloads
        score += peer->nBlocksDownloaded * 10;

        // Penalize if already has many blocks in-flight (spread load)
        score -= peer->nBlocksInFlight * 50;

        if (score > bestScore) {
            bestScore = score;
            bestPeer = peer_id;
        }
    }

    // Use fallback if no suitable peer found
    if (bestPeer == -1 && fallbackPeer != -1) {
        return fallbackPeer;
    }

    return bestPeer;
}

void CBlockFetcher::UpdatePeerStats(NodeId peer, bool success, std::chrono::milliseconds responseTime)
{
    // Note: Caller should hold lock
    // Phase 1: Delegate entirely to CPeerManager (single source of truth)
    if (m_peer_manager) {
        m_peer_manager->UpdatePeerStats(peer, success, responseTime);
    }
}

bool CBlockFetcher::IsDownloading(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return mapBlocksInFlight.count(hash) > 0;
}

bool CBlockFetcher::IsQueued(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return setQueuedHashes.count(hash) > 0;
}

int CBlockFetcher::GetBlocksInFlight() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return mapBlocksInFlight.size();
}

int CBlockFetcher::GetBlocksInFlightForPeer(NodeId peer) const
{
    // Phase 1: Delegate to CPeerManager (single source of truth)
    if (m_peer_manager) {
        return m_peer_manager->GetBlocksInFlightForPeer(peer);
    }
    return 0;
}

size_t CBlockFetcher::GetPendingCount() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    // BUG #158: Return pending count from window or queue
    if (m_window_initialized) {
        return m_download_window.PendingCount();
    }
    return setQueuedHashes.size();
}

size_t CBlockFetcher::GetInFlightCount() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    // BUG #158: Return in-flight count from mapBlocksInFlight
    return mapBlocksInFlight.size();
}

std::vector<uint256> CBlockFetcher::GetQueuedBlocks() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<uint256> result;
    result.reserve(setQueuedHashes.size());

    for (const uint256& hash : setQueuedHashes) {
        result.push_back(hash);
    }

    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

void CBlockFetcher::RemoveFromQueue(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Remove from queued set
    setQueuedHashes.erase(hash);

    // BUG #64: Clean up preferred peer tracking
    mapPreferredPeers.erase(hash);

    // Note: We can't efficiently remove from priority_queue without rebuilding it
    // The item will be skipped when popped in GetNextBlocksToFetch
    // This is acceptable performance-wise as the queue is typically small

}

void CBlockFetcher::OnPeerDisconnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Re-queue all blocks that were in-flight from this peer
    if (mapPeerBlocks.count(peer) > 0) {
        const std::set<uint256>& peerBlocks = mapPeerBlocks[peer];

        for (const uint256& hash : peerBlocks) {
            auto it = mapBlocksInFlight.find(hash);
            if (it != mapBlocksInFlight.end()) {
                int height = it->second.nHeight;
                int retries = it->second.nRetries;

                // Remove from in-flight
                mapBlocksInFlight.erase(it);

                // Phase 1: Notify CPeerManager
        if (m_peer_manager) {
            m_peer_manager->RemoveBlockFromFlight(hash);
        }

                // Re-queue with high priority
                if (retries < MAX_RETRIES) {
                    queueBlocksToFetch.push(BlockDownloadRequest(hash, height, -1, true));
                    setQueuedHashes.insert(hash);
                }
            }
        }

        mapPeerBlocks.erase(peer);
    }

    // IBD Redesign Phase 3: Shadow-track with CBlockTracker
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->OnPeerDisconnected(peer);
    }

    // Phase 1: CPeerManager handles peer state cleanup - we don't track locally
}

void CBlockFetcher::OnPeerConnected(NodeId peer)
{
    // Phase 1: CPeerManager handles peer state initialization - we don't track locally
    // This method is kept for API compatibility but now a no-op
}

bool CBlockFetcher::IsStaleTip() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastBlock = std::chrono::duration_cast<std::chrono::minutes>(
        now - lastBlockReceived
    );

    // Consider stale if no blocks received for 5 minutes and we have queued/in-flight blocks
    bool hasWork = !queueBlocksToFetch.empty() || !mapBlocksInFlight.empty();

    return hasWork && (timeSinceLastBlock >= STALE_TIP_TIMEOUT);
}

void CBlockFetcher::ResetStaleTipTimer()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    lastBlockReceived = std::chrono::steady_clock::now();
}

std::string CBlockFetcher::GetDownloadStatus() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::ostringstream ss;
    ss << "BlockFetcher Status:\n";
    ss << "  Blocks in-flight: " << mapBlocksInFlight.size() << "/" << MAX_BLOCKS_IN_FLIGHT << "\n";
    ss << "  Blocks queued: " << setQueuedHashes.size() << "\n";
    ss << "  Total blocks received: " << nBlocksReceivedTotal << "\n";

    // Phase 1: Peer breakdown from CPeerManager
    if (m_peer_manager) {
        auto peers = m_peer_manager->GetValidPeersForDownload();
        ss << "  Active peers: " << peers.size() << "\n";
        ss << "  Per-peer status:\n";
        for (int peer_id : peers) {
            auto peer = m_peer_manager->GetPeer(peer_id);
            if (peer) {
                ss << "    Peer " << peer_id << ": "
                   << peer->nBlocksInFlight << " in-flight, "
                   << peer->nBlocksDownloaded << " downloaded, "
                   << peer->nStallingCount << " stalls, "
                   << "avg " << peer->avgResponseTime.count() << "ms"
                   << (peer->fPreferredDownload ? " [PREFERRED]" : "")
                   << "\n";
            }
        }
    }

    return ss.str();
}

double CBlockFetcher::GetDownloadSpeed() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Simple calculation: total blocks / time elapsed
    // More sophisticated: could use sliding window
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - lastBlockReceived
    );

    if (elapsed.count() == 0 || nBlocksReceivedTotal == 0) {
        return 0.0;
    }

    return static_cast<double>(nBlocksReceivedTotal) / elapsed.count();
}

void CBlockFetcher::Clear()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    mapBlocksInFlight.clear();
    mapPeerBlocks.clear();

    // Clear priority queue
    while (!queueBlocksToFetch.empty()) {
        queueBlocksToFetch.pop();
    }
    setQueuedHashes.clear();
    mapPreferredPeers.clear();

    // Phase 1: Peer state is in CPeerManager, not cleared here
    nBlocksReceivedTotal = 0;
    lastBlockReceived = std::chrono::steady_clock::now();
}

// Private helper methods

int CBlockFetcher::GetAvailableSlots() const
{
    // Caller should hold lock
    int inFlight = mapBlocksInFlight.size();
    return MAX_BLOCKS_IN_FLIGHT - inFlight;
}

// Phase 1: GetAvailableSlotsForPeer, MarkPeerStalled, IsPeerSuitable removed
// All peer management is now delegated to CPeerManager

void CBlockFetcher::UpdateDownloadSpeed()
{
    // Placeholder for future implementation of sliding window speed calculation
    // Currently speed is calculated on-demand in GetDownloadSpeed()
}

// ============ Per-Block Block Tracking ============

NodeId CBlockFetcher::OnChunkBlockReceived(int height)
{
    // SSOT: Delegate to OnBlockReceived (legacy interface)
    // Return -1 since we don't track which peer sent it (CBlockTracker knows)
    OnBlockReceived(-1, height);
    return -1;
}

// ============ Window Implementation (for backpressure only) ============

void CBlockFetcher::InitializeWindow(int chain_height, int target_height, bool force)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking - no window needed
    if (force && g_node_context.block_tracker) {
        g_node_context.block_tracker->Clear();
    }

    // Keep window for legacy backpressure (will be removed later)
    if (!force && m_window_initialized && m_download_window.GetTargetHeight() == target_height) {
        return;
    }

    m_download_window.Initialize(chain_height, target_height);
    m_window_initialized = true;
}

std::vector<int> CBlockFetcher::GetWindowPendingHeights(int max_count)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Legacy window for backpressure - SSOT uses GetNextBlocksToRequest instead
    if (!m_window_initialized) {
        return {};
    }
    return m_download_window.GetNextPendingHeights(max_count);
}

void CBlockFetcher::MarkWindowHeightsInFlight(const std::vector<int>& heights)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    m_download_window.MarkAsInFlight(heights);
}

void CBlockFetcher::OnWindowBlockReceived(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    m_download_window.OnBlockReceived(height);
}

void CBlockFetcher::OnWindowBlockConnected(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles tracking cleanup via OnBlockReceivedByHeight
    // When a block is connected, it should already have been marked as received

    if (!m_window_initialized) {
        return;
    }

    // Callbacks for legacy window advancement
    auto is_height_queued = [](int h) -> bool {
        if (g_node_context.validation_queue && g_node_context.validation_queue->IsRunning()) {
            return g_node_context.validation_queue->IsHeightQueued(h);
        }
        return false;
    };

    // Check if height is in-flight via CBlockTracker (SSOT)
    auto is_height_in_flight = [](int h) -> bool {
        if (g_node_context.block_tracker) {
            return g_node_context.block_tracker->IsTracked(h);
        }
        return false;
    };

    auto is_height_connected = [](int h) -> bool {
        if (g_node_context.chainstate) {
            int chain_height = g_node_context.chainstate->GetHeight();
            return h <= chain_height;
        }
        return false;
    };

    m_download_window.OnBlockConnected(height, is_height_queued, is_height_in_flight, is_height_connected);
}

void CBlockFetcher::AddHeightsToWindowPending(const std::vector<int>& heights)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    // Add heights to legacy window's pending set (skip those already in-flight via SSOT)
    for (int h : heights) {
        if (g_node_context.block_tracker && g_node_context.block_tracker->IsTracked(h)) {
            continue;  // Already in-flight
        }
        m_download_window.AddToPending(h);
    }
}

bool CBlockFetcher::IsWindowInitialized() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker is always "initialized" - just return true if it exists
    if (g_node_context.block_tracker) {
        return true;
    }
    return m_window_initialized;
}

std::string CBlockFetcher::GetWindowStatus() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: Get status from CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->GetStatus();
    }

    if (!m_window_initialized) {
        return "Window not initialized";
    }
    return m_download_window.GetStatus();
}

bool CBlockFetcher::IsWindowComplete() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: Window is "complete" when no blocks in-flight and chain matches target
    // For now, return false (caller will check chain height vs header height)
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->GetTotalInFlight() == 0;
    }

    if (!m_window_initialized) {
        return false;
    }
    return m_download_window.IsComplete();
}

bool CBlockFetcher::UpdateWindowTarget(int new_target_height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker doesn't need target updates - no window constraint
    // Just update legacy window for backward compatibility
    if (!m_window_initialized) {
        return false;
    }

    return m_download_window.UpdateTargetHeight(new_target_height);
}

// ============ Per-Block Download API (Bitcoin Core Style) ============

std::vector<int> CBlockFetcher::GetNextBlocksToRequest(int max_blocks, int chain_height, int header_height)
{
    std::vector<int> result;
    result.reserve(max_blocks);

    // SSOT: Use CBlockTracker for all tracking
    if (!g_node_context.block_tracker) {
        return result;
    }

    int total_in_flight = g_node_context.block_tracker->GetTotalInFlight();
    if (total_in_flight >= CBlockTracker::MAX_TOTAL) {
        return result;  // Already at capacity
    }

    int available_slots = CBlockTracker::MAX_TOTAL - total_in_flight;
    int blocks_to_get = std::min(max_blocks, available_slots);

    // Pure per-block: iterate from chain_height+1, skip tracked heights
    for (int h = chain_height + 1; h <= header_height && static_cast<int>(result.size()) < blocks_to_get; h++) {
        if (!g_node_context.block_tracker->IsTracked(h)) {
            result.push_back(h);
        }
    }

    return result;
}

bool CBlockFetcher::RequestBlockFromPeer(NodeId peer_id, int height, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking - just delegate to it
    if (!g_node_context.block_tracker) {
        return false;
    }

    // AddBlock handles capacity checks and duplicate detection
    return g_node_context.block_tracker->AddBlock(height, hash, peer_id);
}

bool CBlockFetcher::OnBlockReceived(NodeId peer_id, int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking - just delegate to it
    if (!g_node_context.block_tracker) {
        return false;
    }

    bool found = g_node_context.block_tracker->OnBlockReceivedByHeight(height);

    if (found) {
        // Update stats
        nBlocksReceivedTotal++;
        lastBlockReceived = std::chrono::steady_clock::now();
    }

    return found;
}

std::vector<std::pair<int, NodeId>> CBlockFetcher::GetStalledBlocks(std::chrono::seconds timeout)
{
    // SSOT: Delegate to CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->CheckTimeouts();
    }
    return {};
}

void CBlockFetcher::RequeueBlock(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // SSOT: CBlockTracker handles all tracking
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->RemoveTimedOut(height);
    }
    // Block will be re-requested on next iteration of download loop
}

int CBlockFetcher::GetPeerBlocksInFlight(NodeId peer_id) const
{
    // SSOT: Delegate to CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    }
    return 0;
}

bool CBlockFetcher::IsHeightInFlight(int height) const
{
    // SSOT: Delegate to CBlockTracker
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->IsTracked(height);
    }
    return false;
}
