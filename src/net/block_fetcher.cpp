// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/block_fetcher.h>
// REMOVED: #include <net/node_state.h> - CNodeStateManager replaced by CPeerManager
#include <net/peers.h>       // Phase A: Unified CPeerManager block tracking
#include <core/node_context.h>  // IBD HANG FIX #2: For validation queue access
#include <node/block_validation_queue.h>  // IBD HANG FIX #2: For IsHeightQueued
#include <iostream>
#include <algorithm>
#include <sstream>

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

    // Phase 1: CPeerManager is single source of truth for peer capacity
    if (!m_peer_manager) {
        return false;  // Cannot operate without peer manager
    }

    auto peer_obj = m_peer_manager->GetPeer(peer);
    if (!peer_obj) {
        return false;
    }
    // IBD STUCK FIX #9: Use GetBlocksInFlightForPeer() instead of stale counter
    int blocks_in_flight = m_peer_manager->GetBlocksInFlightForPeer(peer);
    if (blocks_in_flight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    // Check if already in-flight
    if (mapBlocksInFlight.count(hash) > 0) {
        return false;
    }

    // Create in-flight entry (for timeout tracking only)
    CBlockInFlight inFlight(hash, peer, height);
    mapBlocksInFlight[hash] = inFlight;

    // Track peer's blocks (for disconnect handling)
    mapPeerBlocks[peer].insert(hash);

    // Phase 1: CPeerManager is single source of truth for block tracking
    m_peer_manager->MarkBlockAsInFlight(peer, hash, nullptr);

    // Remove from queue if present
    setQueuedHashes.erase(hash);

    // NOTE: Actual GETDATA message sending is handled by caller
    // This function just tracks the request state
    return true;
}

bool CBlockFetcher::MarkBlockReceived(NodeId peer, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Check if block was in-flight in local tracking (for timeout tracking)
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        // Not tracked locally (chunk may have been cancelled/timed out)
        // IBD HANG FIX #13: ALWAYS notify CPeerManager to decrement nBlocksInFlight
        // CPeerManager::MarkBlockAsReceived handles untracked blocks gracefully
        // by decrementing the receiving peer's counter (prevents "all peers at capacity" stall)
        if (m_peer_manager) {
            m_peer_manager->MarkBlockAsReceived(peer, hash);
        }
        return false;  // Still return false so caller knows it wasn't in local tracking
    }

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

    // IBD HANG FIX #22: Check if peer can serve blocks at requested heights
    // Don't request blocks from peers that haven't reached that height yet
    // This prevents requesting blocks from peers like SGP (height=2000) when we need blocks 2225+
    if (peer->start_height < height_end) {
        // Log only occasionally to avoid spam
        static std::map<int, int> skip_count;
        if (++skip_count[peer_id] % 100 == 1) {
            std::cout << "[IBD FIX #22] Skipping peer " << peer_id
                      << " (height=" << peer->start_height
                      << ") for chunk " << height_start << "-" << height_end
                      << " (peer doesn't have these blocks)" << std::endl;
        }
        return false;  // Peer doesn't have blocks at requested heights
    }

    // Validate height range
    if (height_end < height_start) {
        return false;
    }

    // Check no height is already assigned to another peer
    for (int h = height_start; h <= height_end; h++) {
        if (mapHeightToPeer.count(h) > 0 && mapHeightToPeer[h] != peer_id) {
            return false;  // Height already assigned
        }
    }

    int new_blocks = height_end - height_start + 1;

    // Phase 1 FIX: Allow multiple chunks per peer
    // Instead of blocking, EXTEND existing chunk with new heights
    auto it = mapActiveChunks.find(peer_id);
    if (it != mapActiveChunks.end() && !it->second.IsComplete()) {
        PeerChunk& existing = it->second;
        int current_pending = existing.blocks_pending;

        // IBD HANG FIX #11: Match per-peer chunk limit to MAX_BLOCKS_IN_FLIGHT_PER_PEER
        // Previously: max_blocks_per_peer = 4 * 16 = 64 (mismatch with 128 capacity)
        // This caused "no suitable peers" when chunks hit 64 despite 128 capacity
        int max_per_peer = CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER;  // 128
        if (current_pending + new_blocks > max_per_peer) {
            // Peer already has maximum blocks in-flight
            return false;
        }

        // IBD BOTTLENECK FIX #9: Fix chunk extension to only count truly new heights
        // Previously incremented blocks_pending by new_blocks, but this double-counted
        // heights that were already assigned to this peer. Now only counts new assignments.
        int actually_new = 0;
        for (int h = height_start; h <= height_end; h++) {
            if (mapHeightToPeer.count(h) == 0) {
                mapHeightToPeer[h] = peer_id;
                actually_new++;
            } else if (mapHeightToPeer[h] == peer_id) {
                // Already assigned to this peer, just update mapping
                // (no-op, but ensures consistency)
            }
            // If assigned to different peer, skip (already checked above)
        }

        // EXTEND existing chunk: expand range and add only new pending blocks
        existing.height_end = std::max(existing.height_end, height_end);
        existing.height_start = std::min(existing.height_start, height_start);
        existing.blocks_pending += actually_new;  // Only count new heights
        existing.last_activity = std::chrono::steady_clock::now();

        // IBD SLOW FIX #5: Ensure extended heights are tracked in window
        // When chunks extend, heights are added to mapHeightToPeer but may not be in window's m_pending
        // This ensures window state stays consistent with chunk state
        if (m_window_initialized && actually_new > 0) {
            std::vector<int> extended_heights;
            extended_heights.reserve(actually_new);
            for (int h = height_start; h <= height_end; h++) {
                // Check if this height was just assigned to this peer (newly extended)
                if (mapHeightToPeer.count(h) > 0 && mapHeightToPeer[h] == peer_id) {
                    // Only add if not already in window tracking sets
                    if (!m_download_window.IsPending(h) &&
                        !m_download_window.IsInFlight(h) &&
                        !m_download_window.IsReceived(h)) {
                        extended_heights.push_back(h);
                    }
                }
            }
            // Add extended heights to window's pending set
            if (!extended_heights.empty()) {
                for (int h : extended_heights) {
                    m_download_window.AddToPending(h);
                }
            }
        }

        std::cout << "[Chunk] EXTENDED peer " << peer_id << " chunk to "
                  << existing.height_start << "-" << existing.height_end
                  << " (+" << new_blocks << " blocks, total pending=" << existing.blocks_pending << ")" << std::endl;
        return true;
    }

    // Create NEW chunk assignment (no existing chunk or existing is complete)
    PeerChunk chunk(peer_id, height_start, height_end);
    mapActiveChunks[peer_id] = chunk;

    // Map heights to peer
    for (int h = height_start; h <= height_end; h++) {
        mapHeightToPeer[h] = peer_id;
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

    // Update download window tracking (even if height not in chunk)
    if (m_window_initialized && height > 0) {
        m_download_window.OnBlockReceived(height);
    }

    // Find which peer had this height assigned
    auto it = mapHeightToPeer.find(height);
    if (it == mapHeightToPeer.end()) {
        return -1;  // Height not tracked
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

    for (const auto& [peer_id, chunk] : mapActiveChunks) {
        if (chunk.IsComplete()) {
            continue;  // Completed chunks can't stall
        }

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

        if (has_in_flight) {
            // Blocks are still in-flight - don't mark as stalled
            // This handles network delay where blocks take longer than 15s to arrive
            continue;
        }

        // Only check timeout if no blocks are in-flight
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - chunk.last_activity);

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
    // Heights remain in mapHeightToPeer during grace period
    mapCancelledChunks[peer_id] = CancelledChunk(chunk);

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

    // IBD HANG FIX #2: DON'T erase heights from mapHeightToPeer immediately
    // Keep them during grace period so OnChunkBlockReceived() can find them
    // Heights will be erased by CleanupCancelledChunks() after grace period expires

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
              << " will remain tracked for " << CANCELLED_CHUNK_GRACE_PERIOD_SECONDS
              << "s grace period to handle late-arriving blocks" << std::endl;

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
            // Grace period expired - remove cancelled chunk and its height mappings
            std::cout << "[Chunk] Grace period expired for cancelled chunk "
                      << cancelled.chunk.height_start << "-" << cancelled.chunk.height_end
                      << " from peer " << peer_id
                      << " (received " << cancelled.chunk.blocks_received << "/"
                      << cancelled.chunk.ChunkSize() << " blocks during grace period)" << std::endl;

            // Erase height mappings for this cancelled chunk
            for (int h = cancelled.chunk.height_start; h <= cancelled.chunk.height_end; h++) {
                mapHeightToPeer.erase(h);
            }

            to_remove.push_back(peer_id);
        }
    }

    // Remove expired cancelled chunks
    for (NodeId peer_id : to_remove) {
        mapCancelledChunks.erase(peer_id);
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

void CBlockFetcher::InitializeWindow(int chain_height, int target_height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Skip if already initialized with same target
    if (m_window_initialized && m_download_window.GetTargetHeight() == target_height) {
        return;
    }

    m_download_window.Initialize(chain_height, target_height);
    m_window_initialized = true;

    // Also initialize chunk tracking to start from chain_height + 1
    nNextChunkHeight = chain_height + 1;

    std::cout << "[Window] Initialized: " << m_download_window.GetStatus() << std::endl;
}

std::vector<int> CBlockFetcher::GetWindowPendingHeights(int max_count)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

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

    if (!m_window_initialized) {
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

    m_download_window.OnBlockConnected(height, is_height_queued, is_height_in_flight);
}

void CBlockFetcher::AddHeightsToWindowPending(const std::vector<int>& heights)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return;
    }

    // IBD SLOW FIX #3: Add heights to window's pending set
    // This synchronizes QueueMissingBlocks() with the window system
    for (int h : heights) {
        m_download_window.AddToPending(h);
    }
}

bool CBlockFetcher::IsWindowInitialized() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);
    return m_window_initialized;
}

std::string CBlockFetcher::GetWindowStatus() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return "Window not initialized";
    }

    return m_download_window.GetStatus();
}

bool CBlockFetcher::IsWindowComplete() const
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    if (!m_window_initialized) {
        return false;
    }

    return m_download_window.IsComplete();
}

bool CBlockFetcher::UpdateWindowTarget(int new_target_height)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

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
