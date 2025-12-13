// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/block_fetcher.h>
#include <net/node_state.h>  // BUG #69: Bitcoin Core-style per-peer block tracking
#include <net/peers.h>       // Phase A: Unified CPeerManager block tracking
#include <iostream>
#include <algorithm>
#include <sstream>

/**
 * @file block_fetcher.cpp
 * @brief Implementation of parallel block downloading for IBD
 *
 * Implements Bitcoin Core's parallel block download strategy with intelligent
 * peer selection, timeout handling, and priority-based fetching.
 */

CBlockFetcher::CBlockFetcher()
    : nBlocksReceivedTotal(0)
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
    if (!g_peer_manager) {
        return false;  // Cannot operate without peer manager
    }

    auto peer_obj = g_peer_manager->GetPeer(peer);
    if (!peer_obj || peer_obj->nBlocksInFlight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    // Check if already in-flight
    if (mapBlocksInFlight.count(hash) > 0) {
        return false;
    }

    // Create in-flight entry (for timeout tracking only)
    CBlockInFlight inFlight(hash, peer, height);
    mapBlocksInFlight[hash] = inFlight;

    // DEBUG: Log what hash we're storing for later lookup
    std::cout << "[HASH-DEBUG] RequestBlock: storing hash=" << hash.GetHex().substr(0, 16)
              << "... height=" << height << " peer=" << peer
              << " (mapBlocksInFlight size=" << mapBlocksInFlight.size() << ")" << std::endl;
    std::cout.flush();

    // Track peer's blocks (for disconnect handling)
    mapPeerBlocks[peer].insert(hash);

    // Phase 1: CPeerManager is single source of truth for block tracking
    g_peer_manager->MarkBlockAsInFlight(peer, hash, nullptr);

    // Remove from queue if present
    setQueuedHashes.erase(hash);

    // NOTE: Actual GETDATA message sending is handled by caller
    // This function just tracks the request state
    return true;
}

bool CBlockFetcher::MarkBlockReceived(NodeId peer, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // DEBUG: Log what hash we're looking up
    std::cout << "[HASH-DEBUG] MarkBlockReceived: looking for hash=" << hash.GetHex().substr(0, 16)
              << "... peer=" << peer << " (mapBlocksInFlight size=" << mapBlocksInFlight.size() << ")" << std::endl;
    std::cout.flush();

    std::cout << "[DEBUG] MarkBlockReceived(peer=" << peer << ", hash=" << hash.GetHex().substr(0, 16) << ")" << std::endl;

    // Phase 1: CPeerManager is single source of truth - always notify
    if (g_peer_manager) {
        g_peer_manager->MarkBlockAsReceived(peer, hash);
    }

    // Check if block was in-flight in local tracking (for timeout tracking)
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        // Not tracked locally, but CPeerManager was already notified above
        std::cout << "[DEBUG]   hash NOT FOUND in mapBlocksInFlight (size=" << mapBlocksInFlight.size() << ")" << std::endl;
        // Debug: print first few hashes in flight
        int count = 0;
        for (const auto& entry : mapBlocksInFlight) {
            if (count++ < 3) {
                std::cout << "[DEBUG]     in-flight: " << entry.first.GetHex().substr(0, 16) << "... h=" << entry.second.nHeight << std::endl;
            }
        }
        return false;
    }

    int height = it->second.nHeight;

    // Calculate response time and update CPeerManager stats
    auto timeReceived = std::chrono::steady_clock::now();
    auto responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        timeReceived - it->second.timeRequested
    );

    // Phase 1: Delegate peer stats update to CPeerManager
    if (g_peer_manager) {
        g_peer_manager->UpdatePeerStats(peer, true, responseTime);
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

    // Phase 3: Update window state - mark as received
    if (m_window_initialized && height > 0) {
        m_download_window.OnBlockReceived(height);
    }

    // Phase 2: Update chunk tracking
    // Find which peer had this height assigned and update chunk
    auto height_it = mapHeightToPeer.find(height);
    if (height_it != mapHeightToPeer.end()) {
        NodeId chunk_peer = height_it->second;
        auto chunk_it = mapActiveChunks.find(chunk_peer);
        if (chunk_it != mapActiveChunks.end()) {
            PeerChunk& chunk = chunk_it->second;
            if (height >= chunk.height_start && height <= chunk.height_end) {
                chunk.blocks_pending--;
                chunk.blocks_received++;
                chunk.last_activity = timeReceived;

                // If chunk complete, clean up
                if (chunk.IsComplete()) {
                    std::cout << "[Chunk] Peer " << chunk_peer << " completed chunk "
                              << chunk.height_start << "-" << chunk.height_end
                              << " (" << chunk.blocks_received << " blocks)" << std::endl;

                    // Clean up height mappings for this chunk
                    for (int h = chunk.height_start; h <= chunk.height_end; h++) {
                        mapHeightToPeer.erase(h);
                    }

                    // Remove completed chunk
                    mapActiveChunks.erase(chunk_it);
                }
            }
        }
    }

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
        if (g_peer_manager) {
            g_peer_manager->UpdatePeerStats(stalledPeer, false, std::chrono::milliseconds(0));
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
        if (g_peer_manager) {
            g_peer_manager->RemoveBlockFromFlight(hash);
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
    if (!g_peer_manager) {
        return -1;  // Cannot operate without peer manager
    }

    // Try the preferred peer first (the one that announced the block)
    if (preferred_peer != -1 && g_peer_manager->IsPeerSuitableForDownload(preferred_peer)) {
        auto peer = g_peer_manager->GetPeer(preferred_peer);
        if (peer && peer->nBlocksInFlight < CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
            return preferred_peer;
        }
    }

    // Get all valid peers from CPeerManager
    std::vector<int> valid_peers = g_peer_manager->GetValidPeersForDownload();

    NodeId bestPeer = -1;
    NodeId fallbackPeer = -1;
    int bestScore = -1;

    for (int peer_id : valid_peers) {
        auto peer = g_peer_manager->GetPeer(peer_id);
        if (!peer) {
            continue;
        }

        // Must have capacity
        if (peer->nBlocksInFlight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
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
    if (g_peer_manager) {
        g_peer_manager->UpdatePeerStats(peer, success, responseTime);
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
    if (g_peer_manager) {
        return g_peer_manager->GetBlocksInFlightForPeer(peer);
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
                if (g_peer_manager) {
                    g_peer_manager->RemoveBlockFromFlight(hash);
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
    if (g_peer_manager) {
        auto peers = g_peer_manager->GetValidPeersForDownload();
        ss << "  Active peers: " << peers.size() << "\n";
        ss << "  Per-peer status:\n";
        for (int peer_id : peers) {
            auto peer = g_peer_manager->GetPeer(peer_id);
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
    if (!g_peer_manager) {
        return false;
    }

    auto peer = g_peer_manager->GetPeer(peer_id);
    if (!peer || peer->nBlocksInFlight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
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

    // Phase 1 FIX: Allow multiple chunks per peer (up to MAX_CHUNKS_PER_PEER * MAX_BLOCKS_PER_CHUNK)
    // Instead of blocking, EXTEND existing chunk with new heights
    auto it = mapActiveChunks.find(peer_id);
    if (it != mapActiveChunks.end() && !it->second.IsComplete()) {
        PeerChunk& existing = it->second;
        int current_pending = existing.blocks_pending;
        int max_blocks_per_peer = MAX_CHUNKS_PER_PEER * MAX_BLOCKS_PER_CHUNK;  // 4 * 16 = 64

        if (current_pending + new_blocks > max_blocks_per_peer) {
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

    // BUG FIX: Update download window tracking FIRST (even if height not in chunk)
    // This ensures received count is updated for window status reporting
    if (m_window_initialized && height > 0) {
        m_download_window.OnBlockReceived(height);
    }

    // Find which peer had this height assigned
    auto it = mapHeightToPeer.find(height);
    if (it == mapHeightToPeer.end()) {
        return -1;  // Height not tracked
    }

    NodeId peer_id = it->second;

    // Update chunk tracking
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

                // Remove completed chunk
                mapActiveChunks.erase(chunk_it);
            }
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

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - chunk.last_activity);

        if (elapsed.count() >= CHUNK_STALL_TIMEOUT_SECONDS) {
            stalled.emplace_back(peer_id, chunk);
            std::cout << "[Chunk] Peer " << peer_id << " stalled on chunk "
                      << chunk.height_start << "-" << chunk.height_end
                      << " (no activity for " << elapsed.count() << "s)" << std::endl;
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
    if (!g_peer_manager) {
        return false;
    }

    auto new_peer_obj = g_peer_manager->GetPeer(new_peer);
    if (!new_peer_obj || new_peer_obj->nBlocksInFlight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
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

    // Clear height mappings for this chunk
    for (int h = chunk.height_start; h <= chunk.height_end; h++) {
        mapHeightToPeer.erase(h);
    }

    // Mark heights as pending again in the window (if window is initialized)
    if (m_window_initialized) {
        for (int h = chunk.height_start; h <= chunk.height_end; h++) {
            // Only mark as pending if not already received
            if (!m_download_window.IsReceived(h)) {
                m_download_window.MarkAsPending(h);
            }
        }
    }

    // Clear any blocks in-flight from this chunk
    std::vector<uint256> to_remove;
    for (const auto& [hash, in_flight] : mapBlocksInFlight) {
        if (in_flight.peer == peer_id &&
            in_flight.nHeight >= chunk.height_start &&
            in_flight.nHeight <= chunk.height_end) {
            to_remove.push_back(hash);
        }
    }

    for (const uint256& hash : to_remove) {
        mapBlocksInFlight.erase(hash);
        // Also remove from peer tracking
        if (mapPeerBlocks.count(peer_id) > 0) {
            mapPeerBlocks[peer_id].erase(hash);
        }
        // Notify peer manager
        if (g_peer_manager) {
            g_peer_manager->RemoveBlockFromFlight(hash);
        }
    }

    // Remove the chunk
    mapActiveChunks.erase(it);

    std::cout << "[Chunk] Cancelled chunk - peer " << peer_id << " now free for new assignment" << std::endl;

    return true;
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

    m_download_window.OnBlockConnected(height);
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
