// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/block_fetcher.h>
// REMOVED: #include <net/node_state.h> - CNodeStateManager replaced by CPeerManager
#include <net/peers.h>       // Phase A: Unified CPeerManager block tracking
#include <net/block_tracker.h>  // IBD Redesign: Shadow tracking for Phase 3 verification
#include <core/node_context.h>  // IBD HANG FIX #2: For validation queue access
#include <node/block_validation_queue.h>  // IBD HANG FIX #2: For IsHeightQueued
#include <consensus/chain.h>  // BUG #162: For CChainState::GetHeight()
#include <iostream>
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

    std::cout << "[RequestBlock] ENTER peer=" << peer << " height=" << height
              << " hash=" << hash.GetHex().substr(0, 16) << "..." << std::endl;

    // Phase 1: CPeerManager is single source of truth for peer capacity
    if (!m_peer_manager) {
        std::cout << "[RequestBlock] EARLY EXIT: no peer_manager" << std::endl;
        return false;  // Cannot operate without peer manager
    }

    auto peer_obj = m_peer_manager->GetPeer(peer);
    if (!peer_obj) {
        std::cout << "[RequestBlock] EARLY EXIT: peer not found" << std::endl;
        return false;
    }
    // IBD STUCK FIX #9: Use GetBlocksInFlightForPeer() instead of stale counter
    int blocks_in_flight = m_peer_manager->GetBlocksInFlightForPeer(peer);
    std::cout << "[RequestBlock] blocks_in_flight=" << blocks_in_flight
              << " MAX=" << CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER << std::endl;
    if (blocks_in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        std::cout << "[RequestBlock] EARLY EXIT: peer at capacity" << std::endl;
        return false;
    }

    // IBD BOTTLENECK FIX: Skip hash-based duplicate check for mapBlocksInFlight
    // The hash-based check fails when header hash doesn't match received block hash.
    // CBlockTracker handles deduplication by HEIGHT through AssignChunkToPeer.
    // We only check if height is already CONNECTED (block already in chain).
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        BlockState state = g_node_context.block_tracker->GetState(height);
        if (state == BlockState::CONNECTED) {
            // Block already connected to chain - no need to request
            return false;
        }
        // PENDING and IN_FLIGHT are OK - AssignChunkToPeer manages those transitions
    }
    // Note: Removed mapBlocksInFlight.count(hash) check - hash mismatch causes stale entries

    // Create in-flight entry (for timeout tracking only)
    CBlockInFlight inFlight(hash, peer, height);
    mapBlocksInFlight[hash] = inFlight;

    // Track peer's blocks (for disconnect handling)
    mapPeerBlocks[peer].insert(hash);

    // Phase 1: CPeerManager is single source of truth for block tracking
    std::cout << "[RequestBlock] CALLING MarkBlockAsInFlight peer=" << peer << std::endl;
    m_peer_manager->MarkBlockAsInFlight(peer, hash, nullptr);
    std::cout << "[RequestBlock] MarkBlockAsInFlight RETURNED" << std::endl;

    // Remove from queue if present
    setQueuedHashes.erase(hash);

    // NOTE: Actual GETDATA message sending is handled by caller
    // This function just tracks the request state
    std::cout << "[RequestBlock] SUCCESS height=" << height << std::endl;
    return true;
}

bool CBlockFetcher::MarkBlockReceived(NodeId peer, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // BUG #161 DEBUG: Log hash lookup for debugging hash mismatch
    std::cout << "[MarkBlockReceived] ENTRY peer=" << peer
              << " hash=" << hash.GetHex().substr(0, 16) << "..."
              << " mapSize=" << mapBlocksInFlight.size() << std::endl;

    // Check if block was in-flight in local tracking (for timeout tracking)
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        // BUG #161 DEBUG: Log first few hashes in mapBlocksInFlight
        std::cout << "[MarkBlockReceived] NOT FOUND - dumping first 3 in-flight hashes:" << std::endl;
        int count = 0;
        for (const auto& entry : mapBlocksInFlight) {
            if (count++ < 3) {
                std::cout << "  [" << entry.second.nHeight << "] "
                          << entry.first.GetHex().substr(0, 16) << "..." << std::endl;
            }
        }
        // Not tracked locally (chunk may have been cancelled/timed out)
        // IBD HANG FIX #13: ALWAYS notify CPeerManager to decrement nBlocksInFlight
        // CPeerManager::MarkBlockAsReceived handles untracked blocks gracefully
        // by decrementing the receiving peer's counter (prevents "all peers at capacity" stall)
        if (m_peer_manager) {
            m_peer_manager->MarkBlockAsReceived(peer, hash);
        }
        return false;  // Still return false so caller knows it wasn't in local tracking
    }

    std::cout << "[MarkBlockReceived] FOUND height=" << it->second.nHeight << std::endl;

    // Block was in local tracking - notify CPeerManager and continue with stats update
    if (m_peer_manager) {
        m_peer_manager->MarkBlockAsReceived(peer, hash);
    }

    int height = it->second.nHeight;

    // Calculate response time and update CPeerManager stats
    auto timeReceived = std::chrono::steady_clock::now();
    auto responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        timeReceived - it->second.timeRequested
    );

    // Phase 1: Delegate peer stats update to CPeerManager
    if (m_peer_manager) {
        m_peer_manager->UpdatePeerStats(peer, true, responseTime);
    }

    // Remove from local in-flight tracking
    NodeId requestedPeer = it->second.peer;
    mapBlocksInFlight.erase(it);

    // Update peer's block set (for disconnect handling)
    if (mapPeerBlocks.count(requestedPeer) > 0) {
        mapPeerBlocks[requestedPeer].erase(hash);
        if (mapPeerBlocks[requestedPeer].empty()) {
            mapPeerBlocks.erase(requestedPeer);
        }
    }

    // NOTE: Chunk tracking is now handled by OnChunkBlockReceived() which is
    // called explicitly by the caller alongside MarkBlockReceived().
    // This avoids double-counting of blocks_pending decrements.
    // Window tracking is also done in OnChunkBlockReceived().

    // Update global statistics
    nBlocksReceivedTotal++;
    lastBlockReceived = timeReceived;

    // BUG #64: Clean up preferred peer tracking
    mapPreferredPeers.erase(hash);

    return true;
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

// ============ Phase 2: Sequential Chunk Assignment Implementation ============

bool CBlockFetcher::AssignChunkToPeer(NodeId peer_id, int height_start, int height_end)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Validate peer can accept a chunk
    if (!m_peer_manager) {
        return false;
    }

    auto peer = m_peer_manager->GetPeer(peer_id);
    if (!peer) {
        return false;
    }

    // IBD STUCK FIX #9: Use GetBlocksInFlightForPeer() instead of peer->nBlocksInFlight counter
    // The counter can become stale/desync during chunk cancellation, but CPeerManager's
    // mapBlocksInFlight is the single source of truth for tracking state.
    int blocks_in_flight = m_peer_manager->GetBlocksInFlightForPeer(peer_id);
    if (blocks_in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    // IBD FIX: Removed IBD HANG FIX #22 check (peer->start_height < height_end).
    // The check was WRONG - start_height is the chain height when the peer CONNECTED,
    // not the peer's current sync height. Peers serving the blockchain have ALL blocks
    // from genesis, so this check blocked all assignments during IBD when peers connected
    // at a low chain height but we needed higher blocks.

    // Validate height range
    if (height_end < height_start) {
        return false;
    }

    // Check no height is already assigned to another peer (unless that height is in a cancelled chunk)
    // IBD FIX: When a chunk is cancelled, heights remain in mapHeightToPeer during grace period
    // to handle late-arriving blocks. But this blocks reassignment. Allow reassignment if the
    // HEIGHT is within the cancelled chunk's range (not just if the peer has any cancelled chunk).
    for (int h = height_start; h <= height_end; h++) {
        if (mapHeightToPeer.count(h) > 0 && mapHeightToPeer[h] != peer_id) {
            NodeId assigned_peer = mapHeightToPeer[h];
            // Check if the height is within the peer's CANCELLED chunk (not just any cancelled chunk)
            bool height_in_cancelled = false;
            auto cancelled_it = mapCancelledChunks.find(assigned_peer);
            if (cancelled_it != mapCancelledChunks.end()) {
                const CancelledChunk& cancelled = cancelled_it->second;
                if (h >= cancelled.chunk.height_start && h <= cancelled.chunk.height_end) {
                    height_in_cancelled = true;
                }
            }
            bool active = mapActiveChunks.count(assigned_peer) > 0;

            if (height_in_cancelled) {
                // Height is in a cancelled chunk - allow reassignment
                mapHeightToPeer[h] = peer_id;
                continue;  // Height can be reassigned
            }
            // Height is assigned to an active chunk - cannot reassign
            std::cout << "[AssignChunk-DEBUG] FAIL: Height " << h << " assigned to peer " << assigned_peer
                      << " in ACTIVE chunk (not cancelled) - cannot reassign" << std::endl;
            return false;
        }
    }

    // IBD STALL FIX: DON'T extend existing chunks - let other peers take new work
    // Previously: extended one peer's chunk from 1-571, starving other peers
    // Now: each peer gets a fixed-size chunk, parallel download from multiple peers
    auto it = mapActiveChunks.find(peer_id);
    if (it != mapActiveChunks.end() && !it->second.IsComplete()) {
        // Peer already has an active chunk - let other peers take this work
        // DEBUG: Log why we're rejecting this assignment
        std::cout << "[AssignChunk-DEBUG] FAIL: Peer " << peer_id
                  << " has INCOMPLETE active chunk " << it->second.height_start
                  << "-" << it->second.height_end
                  << " (pending=" << it->second.blocks_pending
                  << ", received=" << it->second.blocks_received << ")" << std::endl;
        return false;
    }

    // Create NEW chunk assignment (no existing chunk or existing is complete)
    PeerChunk chunk(peer_id, height_start, height_end);
    mapActiveChunks[peer_id] = chunk;

    // Map heights to peer
    for (int h = height_start; h <= height_end; h++) {
        mapHeightToPeer[h] = peer_id;
    }

    // IBD Redesign Phase 3: Shadow-track with CBlockTracker
    if (g_node_context.block_tracker) {
        for (int h = height_start; h <= height_end; h++) {
            g_node_context.block_tracker->AssignToPeer(h, peer_id);
        }
    }

    std::cout << "[Chunk] Assigned heights " << height_start << "-" << height_end
              << " (" << chunk.ChunkSize() << " blocks) to peer " << peer_id << std::endl;

    return true;
}

std::vector<int> CBlockFetcher::GetNextChunkHeights(int max_blocks)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<int> heights;
    heights.reserve(max_blocks);

    // Start from the next unassigned height
    int h = nNextChunkHeight;
    int count = 0;

    while (count < max_blocks) {
        // Skip heights already assigned
        if (mapHeightToPeer.count(h) > 0) {
            h++;
            continue;
        }

        heights.push_back(h);
        count++;
        h++;
    }

    // Update next chunk start for subsequent calls
    if (!heights.empty()) {
        nNextChunkHeight = heights.back() + 1;
    }

    return heights;
}

NodeId CBlockFetcher::OnChunkBlockReceived(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // ============ Per-Block Tracking (Bitcoin Core Style) ============
    // Check if this block was tracked in the per-block system
    auto perblock_it = mapBlocksInFlightByHeight.find(height);
    if (perblock_it != mapBlocksInFlightByHeight.end()) {
        uint256 hash = perblock_it->second.hash;
        const std::set<NodeId>& all_peers = perblock_it->second.peers;
        NodeId first_peer = all_peers.empty() ? -1 : *all_peers.begin();

        // PARALLEL DOWNLOAD: Remove from ALL peers' tracking
        for (NodeId p : all_peers) {
            auto peer_it = mapPeerBlocksInFlightByHeight.find(p);
            if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
                peer_it->second.erase(height);
                if (peer_it->second.empty()) {
                    mapPeerBlocksInFlightByHeight.erase(peer_it);
                }
            }
        }

        // Remove from per-block tracking
        mapBlocksInFlightByHeight.erase(perblock_it);

        // Notify CPeerManager
        if (m_peer_manager && first_peer >= 0) {
            m_peer_manager->MarkBlockAsReceived(first_peer, hash);
        }

        // Update stats
        nBlocksReceivedTotal++;
        lastBlockReceived = std::chrono::steady_clock::now();

        // Update window
        if (m_window_initialized && height > 0) {
            m_download_window.OnBlockReceived(height);
        }

        std::cout << "[PerBlock] Height " << height << " received (" << all_peers.size() << " peers tracking)" << std::endl;
        return first_peer;
    }

    // ============ Legacy Chunk Tracking (fallback) ============

    // Update download window tracking (even if height not in chunk)
    if (m_window_initialized && height > 0) {
        m_download_window.OnBlockReceived(height);
    }

    // IBD Redesign Phase 3: Shadow-track with CBlockTracker
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->OnBlockReceived(height);
    }

    // Find which peer had this height assigned
    auto it = mapHeightToPeer.find(height);
    if (it == mapHeightToPeer.end()) {
        // STALL FIX: Height not in active tracking - search cancelled chunks
        // After CancelStalledChunk clears heights, late-arriving blocks need this path
        for (auto cancelled_iter = mapCancelledChunks.begin(); cancelled_iter != mapCancelledChunks.end(); ) {
            CancelledChunk& cancelled = cancelled_iter->second;
            if (height >= cancelled.chunk.height_start && height <= cancelled.chunk.height_end) {
                // Found in cancelled chunk - credit the block
                cancelled.chunk.blocks_pending--;
                cancelled.chunk.blocks_received++;
                NodeId found_peer_id = cancelled_iter->first;

                std::cout << "[Chunk] STALL FIX: Late block at height " << height
                          << " found in cancelled chunk " << cancelled.chunk.height_start
                          << "-" << cancelled.chunk.height_end << " from peer " << found_peer_id << std::endl;

                if (cancelled.chunk.IsComplete()) {
                    std::cout << "[Chunk] Cancelled chunk now complete - removing" << std::endl;
                    cancelled_iter = mapCancelledChunks.erase(cancelled_iter);
                }
                return found_peer_id;
            }
            ++cancelled_iter;
        }

        // Height not in any active or cancelled chunk
        if (height <= 500) {
            std::cout << "[OnChunkBlockReceived] Height " << height << " not in any tracking" << std::endl;
        }
        return -1;
    }

    NodeId peer_id = it->second;

    // IBD HANG FIX #3: Check both active and cancelled chunks
    // Blocks can arrive after chunk cancellation (network delay), so we need to handle both cases

    // First, try active chunk
    auto chunk_it = mapActiveChunks.find(peer_id);
    if (chunk_it != mapActiveChunks.end()) {
        PeerChunk& chunk = chunk_it->second;
        if (height >= chunk.height_start && height <= chunk.height_end) {
            chunk.blocks_pending--;
            chunk.blocks_received++;
            chunk.last_activity = std::chrono::steady_clock::now();
            // Debug log for first 200 blocks
            if (height <= 200) {
                std::cout << "[OnChunkBlockReceived] Height " << height << " from peer " << peer_id
                          << " - chunk now has pending=" << chunk.blocks_pending << std::endl;
            }

            // IBD STUCK FIX #12: Erase individual height from mapHeightToPeer immediately
            // Previously only erased when whole chunk completed, causing window to stall
            // because is_height_in_flight_callback returned true for already-received heights
            mapHeightToPeer.erase(height);

            // If chunk complete, clean up
            if (chunk.IsComplete()) {
                std::cout << "[Chunk] Peer " << peer_id << " completed chunk "
                          << chunk.height_start << "-" << chunk.height_end
                          << " (" << chunk.blocks_received << " blocks)" << std::endl;

                // Clean up height mappings for this chunk
                for (int h = chunk.height_start; h <= chunk.height_end; h++) {
                    mapHeightToPeer.erase(h);
                }

                // IBD HANG FIX #21: On chunk completion, ONLY clean up CBlockFetcher's local tracking
                // Do NOT call RemoveBlockFromFlight() - that causes double-decrement because:
                // 1. Block arrives → MarkBlockReceived() → CPeerManager::MarkBlockAsReceived() → decrement
                // 2. Chunk completes → Fix #19 → RemoveBlockFromFlight() → decrement AGAIN!
                // Instead, let CPeerManager naturally handle block arrivals via MarkBlockAsReceived().
                // Only clean up local timeout tracking to prevent stale entries.
                {
                    int blocks_removed = 0;
                    for (auto block_it = mapBlocksInFlight.begin(); block_it != mapBlocksInFlight.end(); ) {
                        if (block_it->second.peer == peer_id) {
                            // Only remove from CBlockFetcher's map, NOT from CPeerManager
                            block_it = mapBlocksInFlight.erase(block_it);
                            blocks_removed++;
                        } else {
                            ++block_it;
                        }
                    }
                    mapPeerBlocks.erase(peer_id);
                    if (blocks_removed > 0) {
                        std::cout << "[Chunk] Cleaned up " << blocks_removed
                                  << " local tracking entries for peer " << peer_id << std::endl;
                    }
                }

                // Remove completed chunk
                mapActiveChunks.erase(chunk_it);
            }
            return peer_id;
        }
    }

    // IBD HANG FIX #3: Check cancelled chunks (grace period)
    // Block arrived after chunk cancellation - still credit it to the cancelled chunk
    auto cancelled_it = mapCancelledChunks.find(peer_id);
    if (cancelled_it != mapCancelledChunks.end()) {
        CancelledChunk& cancelled = cancelled_it->second;
        if (height >= cancelled.chunk.height_start && height <= cancelled.chunk.height_end) {
            // Update cancelled chunk stats (for logging/debugging)
            cancelled.chunk.blocks_pending--;
            cancelled.chunk.blocks_received++;
            
            std::cout << "[Chunk] Late-arriving block at height " << height
                      << " credited to cancelled chunk " << cancelled.chunk.height_start
                      << "-" << cancelled.chunk.height_end << " from peer " << peer_id
                      << " (received " << cancelled.chunk.blocks_received << "/"
                      << cancelled.chunk.ChunkSize() << " blocks)" << std::endl;

            // Remove height from mapHeightToPeer (block arrived, no longer need tracking)
            mapHeightToPeer.erase(height);

            // If cancelled chunk is now complete, remove it immediately
            if (cancelled.chunk.IsComplete()) {
                std::cout << "[Chunk] Cancelled chunk " << cancelled.chunk.height_start
                          << "-" << cancelled.chunk.height_end << " from peer " << peer_id
                          << " is now complete - removing from cancelled map" << std::endl;
                
                // Erase remaining heights for this cancelled chunk
                for (int h = cancelled.chunk.height_start; h <= cancelled.chunk.height_end; h++) {
                    mapHeightToPeer.erase(h);
                }
                
                mapCancelledChunks.erase(cancelled_it);
            }
            return peer_id;
        }
    }

    return peer_id;
}

std::vector<std::pair<NodeId, PeerChunk>> CBlockFetcher::CheckStalledChunks()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<std::pair<NodeId, PeerChunk>> stalled;
    auto now = std::chrono::steady_clock::now();

    // IBD STALL FIX: Maximum time a chunk can have blocks in-flight without progress
    // This catches peers that have blocks in-flight but send wrong blocks
    // Reduced from 60s to 20s for faster recovery from non-delivering peers
    static constexpr int MAX_IN_FLIGHT_SECONDS = 20;

    for (const auto& [peer_id, chunk] : mapActiveChunks) {
        if (chunk.IsComplete()) {
            continue;  // Completed chunks can't stall
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - chunk.last_activity);

        // IBD HANG FIX #1: Check if blocks are still in-flight before marking as stalled
        // Prevents premature cancellation when blocks are still in transit (network delay)
        bool has_in_flight = false;
        for (const auto& [hash, in_flight] : mapBlocksInFlight) {
            if (in_flight.peer == peer_id &&
                in_flight.nHeight >= chunk.height_start &&
                in_flight.nHeight <= chunk.height_end) {
                has_in_flight = true;
                break;
            }
        }

        // IBD STALL FIX: Even if blocks are in-flight, cancel if no progress for too long
        // This catches peers that have in-flight entries but send wrong blocks
        if (has_in_flight && elapsed.count() >= MAX_IN_FLIGHT_SECONDS) {
            stalled.emplace_back(peer_id, chunk);
            std::cout << "[Chunk] Peer " << peer_id << " stalled on chunk "
                      << chunk.height_start << "-" << chunk.height_end
                      << " (no progress for " << elapsed.count() << "s despite in-flight blocks)" << std::endl;
            continue;
        }

        if (has_in_flight) {
            // Blocks are still in-flight and under max time - don't mark as stalled
            continue;
        }

        // No blocks in-flight - check normal timeout
        if (elapsed.count() >= CHUNK_STALL_TIMEOUT_SECONDS) {
            stalled.emplace_back(peer_id, chunk);
            std::cout << "[Chunk] Peer " << peer_id << " stalled on chunk "
                      << chunk.height_start << "-" << chunk.height_end
                      << " (no activity for " << elapsed.count() << "s, no blocks in-flight)" << std::endl;
        }
    }

    return stalled;
}

bool CBlockFetcher::ReassignChunk(NodeId old_peer, NodeId new_peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Find old peer's chunk
    auto old_it = mapActiveChunks.find(old_peer);
    if (old_it == mapActiveChunks.end()) {
        return false;
    }

    PeerChunk& old_chunk = old_it->second;

    // Validate new peer
    if (!m_peer_manager) {
        return false;
    }

    auto new_peer_obj = m_peer_manager->GetPeer(new_peer);
    if (!new_peer_obj) {
        return false;
    }
    // IBD STUCK FIX #9: Use GetBlocksInFlightForPeer() instead of stale counter
    int new_peer_in_flight = m_peer_manager->GetBlocksInFlightForPeer(new_peer);
    if (new_peer_in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    // Check new peer doesn't already have a chunk
    if (mapActiveChunks.count(new_peer) > 0 && !mapActiveChunks[new_peer].IsComplete()) {
        return false;
    }

    // Create new chunk with remaining blocks
    PeerChunk new_chunk(new_peer, old_chunk.height_start, old_chunk.height_end);
    new_chunk.blocks_pending = old_chunk.blocks_pending;
    new_chunk.blocks_received = old_chunk.blocks_received;

    // Update height mappings
    for (int h = old_chunk.height_start; h <= old_chunk.height_end; h++) {
        if (mapHeightToPeer.count(h) > 0 && mapHeightToPeer[h] == old_peer) {
            mapHeightToPeer[h] = new_peer;
        }
    }

    // Remove old, add new
    mapActiveChunks.erase(old_it);
    mapActiveChunks[new_peer] = new_chunk;

    std::cout << "[Chunk] Reassigned chunk " << new_chunk.height_start << "-" << new_chunk.height_end
              << " from peer " << old_peer << " to peer " << new_peer << std::endl;

    return true;
}

bool CBlockFetcher::CancelStalledChunk(NodeId peer_id)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Find peer's chunk
    auto it = mapActiveChunks.find(peer_id);
    if (it == mapActiveChunks.end()) {
        return false;
    }

    PeerChunk& chunk = it->second;

    std::cout << "[Chunk] Cancelling stalled chunk " << chunk.height_start << "-" << chunk.height_end
              << " from peer " << peer_id << " (received " << chunk.blocks_received << "/"
              << chunk.ChunkSize() << " blocks)" << std::endl;

    // IBD HANG FIX #2: Move chunk to cancelled map instead of erasing immediately
    // This allows blocks that arrive after cancellation (network delay) to be properly tracked
    mapCancelledChunks[peer_id] = CancelledChunk(chunk);

    // STALL FIX: Clear heights from mapHeightToPeer IMMEDIATELY
    // This allows other peers to take over these heights right away
    // Late-arriving blocks are handled via cancelled chunk search in OnChunkBlockReceived()
    int heights_cleared = 0;
    for (int h = chunk.height_start; h <= chunk.height_end; h++) {
        if (mapHeightToPeer.erase(h) > 0) {
            heights_cleared++;
        }
    }
    std::cout << "[Chunk] STALL FIX: Cleared " << heights_cleared << " heights from mapHeightToPeer for immediate reassignment" << std::endl;

    // IBD WINDOW FIX: Reset nNextChunkHeight if cancelled chunk is below current position
    // This prevents the window from advancing past undelivered blocks
    std::cout << "[Chunk] WINDOW CHECK: chunk.height_start=" << chunk.height_start
              << " nNextChunkHeight=" << nNextChunkHeight << std::endl;
    if (chunk.height_start < nNextChunkHeight) {
        std::cout << "[Chunk] WINDOW FIX: Resetting nNextChunkHeight from " << nNextChunkHeight
                  << " to " << chunk.height_start << " (cancelled chunk start)" << std::endl;
        nNextChunkHeight = chunk.height_start;
    }

    // Mark heights as pending again in the window (if window is initialized)
    // This allows them to be re-requested if blocks don't arrive during grace period
    if (m_window_initialized) {
        for (int h = chunk.height_start; h <= chunk.height_end; h++) {
            // Only mark as pending if not already received
            if (!m_download_window.IsReceived(h)) {
                m_download_window.MarkAsPending(h);
            }
        }
    }

    // IBD HANG FIX #16: Remove all blocks for this peer from CPeerManager tracking
    // This decrements nBlocksInFlight so the peer can accept new chunks
    // Without this fix, peers get stuck at "capacity" (128 blocks) forever
    // IBD STUCK FIX #1: Also remove from CPeerManager::mapBlocksInFlight to fix tracking desync
    if (m_peer_manager) {
        int blocks_removed = 0;
        int cpmanager_blocks_removed = 0;
        
        // Remove from CBlockFetcher::mapBlocksInFlight
        for (auto block_it = mapBlocksInFlight.begin(); block_it != mapBlocksInFlight.end(); ) {
            if (block_it->second.peer == peer_id) {
                m_peer_manager->RemoveBlockFromFlight(block_it->first);
                block_it = mapBlocksInFlight.erase(block_it);
                blocks_removed++;
            } else {
                ++block_it;
            }
        }
        
        // IBD STUCK FIX #1: Also remove from CPeerManager::mapBlocksInFlight
        // This fixes tracking desync where blocks remain in CPeerManager after chunk cancellation
        // Use GetBlocksInFlight() to get all blocks, then remove ones for this peer
        std::vector<std::pair<uint256, int>> all_blocks = m_peer_manager->GetBlocksInFlight();
        for (const auto& block_entry : all_blocks) {
            if (block_entry.second == peer_id) {
                m_peer_manager->RemoveBlockFromFlight(block_entry.first);
                cpmanager_blocks_removed++;
            }
        }
        
        // Also clean up mapPeerBlocks
        mapPeerBlocks.erase(peer_id);
        std::cout << "[Chunk] IBD STUCK FIX #1: Removed " << blocks_removed 
                  << " blocks from CBlockFetcher and " << cpmanager_blocks_removed
                  << " blocks from CPeerManager for peer " << peer_id 
                  << " (nBlocksInFlight decremented)" << std::endl;
    }

    // Remove the chunk from active chunks (moved to cancelled)
    mapActiveChunks.erase(it);

    std::cout << "[Chunk] Cancelled chunk - peer " << peer_id << " now free for new assignment" << std::endl;
    std::cout << "[Chunk] Heights " << chunk.height_start << "-" << chunk.height_end
              << " cleared and available for immediate reassignment" << std::endl;

    return true;
}

void CBlockFetcher::CleanupCancelledChunks()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto now = std::chrono::steady_clock::now();
    std::vector<NodeId> to_remove;

    for (const auto& [peer_id, cancelled] : mapCancelledChunks) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - cancelled.cancelled_time);

        if (elapsed.count() >= CANCELLED_CHUNK_GRACE_PERIOD_SECONDS) {
            // Grace period expired - remove cancelled chunk entry
            // STALL FIX: Heights already cleared in CancelStalledChunk, just log and remove
            std::cout << "[Chunk] Grace period expired for cancelled chunk "
                      << cancelled.chunk.height_start << "-" << cancelled.chunk.height_end
                      << " from peer " << peer_id
                      << " (received " << cancelled.chunk.blocks_received << "/"
                      << cancelled.chunk.ChunkSize() << " blocks during grace period)" << std::endl;

            to_remove.push_back(peer_id);
        }
    }

    // Remove expired cancelled chunks
    for (NodeId peer_id : to_remove) {
        mapCancelledChunks.erase(peer_id);
    }
}

void CBlockFetcher::CleanupUnsuitablePeers()
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_peer_manager) {
        return;
    }

    // BUG #165 FIX: Clean up mapBlocksInFlight entries from unsuitable peers
    // When a peer becomes unsuitable (stall count too high), their in-flight entries
    // become zombie entries that block the system. Clean them up proactively.

    // Find all unsuitable peers that have entries in mapBlocksInFlight
    std::set<NodeId> unsuitable_peers_with_entries;
    for (const auto& entry : mapBlocksInFlight) {
        NodeId peer_id = entry.second.peer;
        if (!m_peer_manager->IsPeerSuitableForDownload(peer_id)) {
            unsuitable_peers_with_entries.insert(peer_id);
        }
    }

    if (unsuitable_peers_with_entries.empty()) {
        return;
    }

    // Clean up entries for each unsuitable peer
    for (NodeId peer_id : unsuitable_peers_with_entries) {
        int local_removed = 0;
        int cpmanager_removed = 0;

        // Remove from CBlockFetcher::mapBlocksInFlight
        for (auto it = mapBlocksInFlight.begin(); it != mapBlocksInFlight.end(); ) {
            if (it->second.peer == peer_id) {
                // Also remove from CPeerManager
                m_peer_manager->RemoveBlockFromFlight(it->first);
                it = mapBlocksInFlight.erase(it);
                local_removed++;
            } else {
                ++it;
            }
        }

        // Clean up mapPeerBlocks
        mapPeerBlocks.erase(peer_id);

        // Also clean up any remaining entries in CPeerManager (may have entries we don't track locally)
        std::vector<std::pair<uint256, int>> all_blocks = m_peer_manager->GetBlocksInFlight();
        for (const auto& block_entry : all_blocks) {
            if (block_entry.second == peer_id) {
                m_peer_manager->RemoveBlockFromFlight(block_entry.first);
                cpmanager_removed++;
            }
        }

        if (local_removed > 0 || cpmanager_removed > 0) {
            std::cout << "[BUG #165 FIX] Cleaned up " << local_removed << " local + "
                      << cpmanager_removed << " CPeerManager entries for unsuitable peer " << peer_id
                      << std::endl;
        }

        // BUG #166 FIX: Clear the peer's vBlocksInFlight and reset stall count
        // This is critical! Even if mapBlocksInFlight cleanup worked, vBlocksInFlight may have
        // orphaned entries due to desync. Clearing vBlocksInFlight stops CheckForStallingPeers
        // from timing out stale entries and incrementing stall count forever.
        // Resetting stall count allows the peer to become suitable again.
        m_peer_manager->ClearPeerInFlightState(peer_id);

        // Also cancel their active chunk if they have one
        auto chunk_it = mapActiveChunks.find(peer_id);
        if (chunk_it != mapActiveChunks.end()) {
            std::cout << "[BUG #165 FIX] Cancelling chunk " << chunk_it->second.height_start
                      << "-" << chunk_it->second.height_end << " from unsuitable peer " << peer_id
                      << std::endl;

            // Mark heights as pending for re-request
            if (m_window_initialized) {
                for (int h = chunk_it->second.height_start; h <= chunk_it->second.height_end; h++) {
                    if (!m_download_window.IsReceived(h)) {
                        m_download_window.MarkAsPending(h);
                    }
                }
            }

            // Erase height mappings
            for (int h = chunk_it->second.height_start; h <= chunk_it->second.height_end; h++) {
                mapHeightToPeer.erase(h);
            }

            mapActiveChunks.erase(chunk_it);
        }
    }
}

void CBlockFetcher::UpdateChunkActivity(NodeId peer_id)
{
    // BUG #155 FIX: Update last_activity after sending GETDATA
    // This prevents false stall detection when network is slow
    std::lock_guard<std::mutex> lock(cs_fetcher);
    auto it = mapActiveChunks.find(peer_id);
    if (it != mapActiveChunks.end()) {
        it->second.last_activity = std::chrono::steady_clock::now();
        std::cout << "[Chunk] Updated activity timer for peer " << peer_id
                  << " chunk " << it->second.height_start << "-" << it->second.height_end << std::endl;
    }
}

NodeId CBlockFetcher::GetPeerForHeight(int height) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto it = mapHeightToPeer.find(height);
    if (it != mapHeightToPeer.end()) {
        return it->second;
    }
    return -1;
}

const PeerChunk* CBlockFetcher::GetPeerChunk(NodeId peer_id) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto it = mapActiveChunks.find(peer_id);
    if (it != mapActiveChunks.end()) {
        return &it->second;
    }
    return nullptr;
}

std::string CBlockFetcher::GetChunkStatus() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::ostringstream ss;
    ss << "Chunk Status:\n";
    ss << "  Next chunk height: " << nNextChunkHeight << "\n";
    ss << "  Active chunks: " << mapActiveChunks.size() << "\n";
    ss << "  Heights assigned: " << mapHeightToPeer.size() << "\n";

    for (const auto& [peer_id, chunk] : mapActiveChunks) {
        ss << "  Peer " << peer_id << ": heights " << chunk.height_start << "-" << chunk.height_end
           << " (" << chunk.blocks_received << "/" << chunk.ChunkSize() << " received)\n";
    }

    return ss.str();
}

// ============ Phase 3: Moving Window Implementation ============

void CBlockFetcher::InitializeWindow(int chain_height, int target_height, bool force)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: CBlockTracker is now PRIMARY source of truth
    // Skip if already initialized with same target (unless forced for fork recovery)
    if (g_node_context.block_tracker) {
        if (!force && g_node_context.block_tracker->IsInitialized() &&
            g_node_context.block_tracker->GetTargetHeight() == target_height) {
            return;
        }
    } else if (!force && m_window_initialized && m_download_window.GetTargetHeight() == target_height) {
        return;  // Fallback to old check if block_tracker not available
    }

    // BUG #159 FIX: Clear existing state when force reinitializing for fork recovery
    if (force) {
        std::cout << "[Window] Force reinitializing for fork recovery (chain_height=" << chain_height << ")" << std::endl;
        // Clear all in-flight blocks to start fresh from fork point
        mapBlocksInFlight.clear();
        // Clear chunk assignments
        mapActiveChunks.clear();
        mapHeightToPeer.clear();
        mapCancelledChunks.clear();
    }

    // IBD Redesign Phase 4: Initialize CBlockTracker as PRIMARY
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->Initialize(chain_height, target_height);
        std::cout << "[IBD] CBlockTracker initialized: " << g_node_context.block_tracker->GetStatus() << std::endl;
    }

    // Legacy: Keep old systems in sync for now (will be removed in Phase 5)
    m_download_window.Initialize(chain_height, target_height);
    m_window_initialized = true;
    nNextChunkHeight = chain_height + 1;

    std::cout << "[Window] Initialized: " << m_download_window.GetStatus() << std::endl;
}

std::vector<int> CBlockFetcher::GetWindowPendingHeights(int max_count)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        return g_node_context.block_tracker->GetPendingHeights(max_count);
    }

    // Fallback to legacy window
    if (!m_window_initialized) {
        return {};
    }
    return m_download_window.GetNextPendingHeights(max_count);
}

void CBlockFetcher::MarkWindowHeightsInFlight(const std::vector<int>& heights)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        std::cout << "[MarkWindowHeightsInFlight] Window not initialized, skipping" << std::endl;
        return;
    }

    std::cout << "[MarkWindowHeightsInFlight] Removing " << heights.size() << " heights from m_pending" << std::endl;
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

    std::cout << "[OnWindowBlockConnected] height=" << height << " window_initialized=" << m_window_initialized << std::endl;

    // BUG #163 FIX: Clean up mapBlocksInFlight by HEIGHT when block is connected
    // This fixes the 128-block stall where blocks arrive with different hashes than requested
    // (due to FastHash vs RandomX hash mismatch). The blocks connect to the chain but
    // mapBlocksInFlight entries are never removed because MarkBlockReceived() can't find them.
    // By cleaning up by height, we prevent mapBlocksInFlight from filling up with stale entries.
    for (auto it = mapBlocksInFlight.begin(); it != mapBlocksInFlight.end(); ) {
        if (it->second.nHeight == height) {
            std::cout << "[BUG #163 FIX] Cleaning up in-flight entry for connected height " << height
                      << " hash=" << it->first.GetHex().substr(0, 16) << "..." << std::endl;
            // Also clean up peer tracking
            if (mapPeerBlocks.count(it->second.peer) > 0) {
                mapPeerBlocks[it->second.peer].erase(it->first);
                if (mapPeerBlocks[it->second.peer].empty()) {
                    mapPeerBlocks.erase(it->second.peer);
                }
            }
            // Notify CPeerManager
            if (m_peer_manager) {
                m_peer_manager->RemoveBlockFromFlight(it->first);
            }
            it = mapBlocksInFlight.erase(it);
        } else {
            ++it;
        }
    }

    if (!m_window_initialized) {
        std::cout << "[OnWindowBlockConnected] Window not initialized, skipping" << std::endl;
        return;
    }

    // IBD HANG FIX #2: Pass callback to check if height is queued for validation
    // This allows window to advance past blocks that are queued (processing) vs stuck
    // IBD STUCK FIX #6: Pass callback to check if height is in-flight via chunk tracking
    // This prevents window from advancing past heights that are still being fetched
    auto is_height_queued = [](int h) -> bool {
        if (g_node_context.validation_queue && g_node_context.validation_queue->IsRunning()) {
            return g_node_context.validation_queue->IsHeightQueued(h);
        }
        return false;
    };

    // IBD STUCK FIX #6: Check if height is assigned to a peer (in-flight via chunk system)
    // This uses mapHeightToPeer to determine if a height is currently being fetched
    auto is_height_in_flight = [this](int h) -> bool {
        // Note: cs_fetcher already held by caller
        return mapHeightToPeer.count(h) > 0;
    };

    // BUG #162 FIX: Check if height is connected to the chain
    // This is the authoritative check - a height is complete only if it's at or below chain tip
    auto is_height_connected = [](int h) -> bool {
        if (g_node_context.chainstate) {
            int chain_height = g_node_context.chainstate->GetHeight();
            return h <= chain_height;
        }
        return false;
    };

    // IBD Redesign Phase 3: Shadow-track with CBlockTracker
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->OnBlockConnected(height);
    }

    m_download_window.OnBlockConnected(height, is_height_queued, is_height_in_flight, is_height_connected);
}

void CBlockFetcher::AddHeightsToWindowPending(const std::vector<int>& heights)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    // IBD SLOW FIX #3: Add heights to window's pending set
    // This synchronizes QueueMissingBlocks() with the window system
    // IBD FIX: Skip heights that are already assigned to peers (in mapHeightToPeer)
    // These heights are in-flight and should not be added back to m_pending
    for (int h : heights) {
        if (mapHeightToPeer.count(h) > 0) {
            // Height is assigned to a peer - don't add to pending
            continue;
        }
        m_download_window.AddToPending(h);

        // Phase 5: Also add to CBlockTracker if height is beyond current window
        // This handles heights added by QueueMissingBlocks that weren't in initial window
        if (g_node_context.block_tracker) {
            g_node_context.block_tracker->AddPendingHeight(h);
        }
    }
}

bool CBlockFetcher::IsWindowInitialized() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->IsInitialized();
    }
    return m_window_initialized;
}

std::string CBlockFetcher::GetWindowStatus() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
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

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker && g_node_context.block_tracker->IsInitialized()) {
        return g_node_context.block_tracker->IsComplete();
    }

    if (!m_window_initialized) {
        return false;
    }
    return m_download_window.IsComplete();
}

bool CBlockFetcher::UpdateWindowTarget(int new_target_height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // IBD Redesign Phase 4: Use CBlockTracker as PRIMARY
    if (g_node_context.block_tracker) {
        g_node_context.block_tracker->UpdateTarget(new_target_height);
    }

    if (!m_window_initialized) {
        return false;
    }

    bool updated = m_download_window.UpdateTargetHeight(new_target_height);
    if (updated) {
        std::cout << "[IBD] IBD HANG FIX #15: Updated window target to " << new_target_height
                  << " - " << m_download_window.GetStatus() << std::endl;
    }
    return updated;
}

// ============ Per-Block Download API (Bitcoin Core Style) ============

std::vector<int> CBlockFetcher::GetNextBlocksToRequest(int max_blocks)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<int> result;
    result.reserve(max_blocks);

    // Get pending heights from window
    if (!m_window_initialized) {
        return result;
    }

    // Get all pending heights (not just consecutive)
    auto pending = m_download_window.GetNextPendingHeights(max_blocks * 2);  // Get more to filter

    for (int h : pending) {
        if (static_cast<int>(result.size()) >= max_blocks) break;

        // Skip if already in-flight (per-block tracking)
        if (mapBlocksInFlightByHeight.count(h) > 0) {
            continue;
        }

        // Skip if already in-flight (legacy chunk tracking)
        if (mapHeightToPeer.count(h) > 0) {
            continue;
        }

        result.push_back(h);
    }

    return result;
}

bool CBlockFetcher::RequestBlockFromPeer(NodeId peer_id, int height, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Check peer capacity using per-block tracking
    auto peer_it = mapPeerBlocksInFlightByHeight.find(peer_id);
    if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
        if (static_cast<int>(peer_it->second.size()) >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            return false;  // Peer at capacity
        }
    }

    // Check if height already in-flight
    auto block_it = mapBlocksInFlightByHeight.find(height);
    if (block_it != mapBlocksInFlightByHeight.end()) {
        // PARALLEL DOWNLOAD: Height already in-flight
        // Check if THIS peer already has it (reject duplicate)
        if (block_it->second.HasPeer(peer_id)) {
            return false;  // This peer already downloading this block
        }
        // Add this peer as parallel downloader
        block_it->second.AddPeer(peer_id);
        mapPeerBlocksInFlightByHeight[peer_id].insert(height);

        // Notify CPeerManager
        if (m_peer_manager) {
            m_peer_manager->MarkBlockAsInFlight(peer_id, hash, nullptr);
        }

        std::cout << "[PerBlock] PARALLEL: Added peer " << peer_id << " for height " << height
                  << " (now " << block_it->second.peers.size() << " peers)" << std::endl;
        return true;
    }

    // First request for this height
    mapBlocksInFlightByHeight[height] = BlockInFlightByHeight(height, hash, peer_id);
    mapPeerBlocksInFlightByHeight[peer_id].insert(height);

    // Update window state
    m_download_window.MarkAsInFlight({height});

    // Notify CPeerManager
    if (m_peer_manager) {
        m_peer_manager->MarkBlockAsInFlight(peer_id, hash, nullptr);
    }

    std::cout << "[PerBlock] Requested height " << height << " from peer " << peer_id
              << " (peer now has " << mapPeerBlocksInFlightByHeight[peer_id].size() << " in-flight)" << std::endl;

    return true;
}

bool CBlockFetcher::OnBlockReceived(NodeId peer_id, int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Find in per-block tracking
    auto it = mapBlocksInFlightByHeight.find(height);
    if (it == mapBlocksInFlightByHeight.end()) {
        // Not in per-block tracking - try legacy chunk system
        return false;
    }

    uint256 hash = it->second.hash;
    const std::set<NodeId>& all_peers = it->second.peers;

    // PARALLEL DOWNLOAD: Remove from ALL peers' tracking (they were all racing)
    for (NodeId p : all_peers) {
        auto peer_it = mapPeerBlocksInFlightByHeight.find(p);
        if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                mapPeerBlocksInFlightByHeight.erase(peer_it);
            }
        }
        // Notify CPeerManager for each peer
        if (m_peer_manager && p != peer_id) {
            m_peer_manager->RemoveBlockFromFlight(hash);  // Clean up other peers
        }
    }

    // Remove from per-block tracking
    mapBlocksInFlightByHeight.erase(it);

    // Update window state
    m_download_window.OnBlockReceived(height);

    // Notify CPeerManager - mark received from delivering peer
    if (m_peer_manager) {
        m_peer_manager->MarkBlockAsReceived(peer_id, hash);
    }

    // Update stats
    nBlocksReceivedTotal++;
    lastBlockReceived = std::chrono::steady_clock::now();

    std::cout << "[PerBlock] Received height " << height << " from peer " << peer_id << std::endl;

    return true;
}

std::vector<std::pair<int, NodeId>> CBlockFetcher::GetStalledBlocks(std::chrono::seconds timeout)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::vector<std::pair<int, NodeId>> stalled;
    auto now = std::chrono::steady_clock::now();

    for (const auto& [height, info] : mapBlocksInFlightByHeight) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - info.first_request_time);
        if (elapsed >= timeout) {
            // Return first peer for logging, but caller should add parallel peer, not requeue
            NodeId first_peer = info.peers.empty() ? -1 : *info.peers.begin();
            stalled.push_back({height, first_peer});
        }
    }

    if (!stalled.empty()) {
        std::cout << "[PerBlock] Found " << stalled.size() << " blocks needing parallel download (timeout=" << timeout.count() << "s)" << std::endl;
    }

    return stalled;
}

void CBlockFetcher::RequeueBlock(int height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Remove from per-block tracking if present
    auto it = mapBlocksInFlightByHeight.find(height);
    if (it != mapBlocksInFlightByHeight.end()) {
        uint256 hash = it->second.hash;
        const std::set<NodeId>& peers = it->second.peers;

        // Remove from ALL peers' tracking (parallel download support)
        for (NodeId peer : peers) {
            auto peer_it = mapPeerBlocksInFlightByHeight.find(peer);
            if (peer_it != mapPeerBlocksInFlightByHeight.end()) {
                peer_it->second.erase(height);
                if (peer_it->second.empty()) {
                    mapPeerBlocksInFlightByHeight.erase(peer_it);
                }
            }
        }

        // Remove from in-flight map
        mapBlocksInFlightByHeight.erase(it);

        // Notify CPeerManager
        if (m_peer_manager) {
            m_peer_manager->RemoveBlockFromFlight(hash);
        }

        std::cout << "[PerBlock] Requeued height " << height << " (was assigned to " << peers.size() << " peers)" << std::endl;
    }

    // Add back to pending
    m_download_window.MarkAsPending(height);
}

int CBlockFetcher::GetPeerBlocksInFlight(NodeId peer_id) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto it = mapPeerBlocksInFlightByHeight.find(peer_id);
    if (it != mapPeerBlocksInFlightByHeight.end()) {
        return static_cast<int>(it->second.size());
    }
    return 0;
}

bool CBlockFetcher::IsHeightInFlight(int height) const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Check per-block tracking
    if (mapBlocksInFlightByHeight.count(height) > 0) {
        return true;
    }

    // Check legacy chunk tracking
    if (mapHeightToPeer.count(height) > 0) {
        return true;
    }

    return false;
}
