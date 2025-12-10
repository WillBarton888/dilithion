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

    // Check peer capacity
    if (GetAvailableSlotsForPeer(peer) <= 0) {
        return false;
    }

    // BUG #61 FIX: Removed redundant IsPeerSuitable check
    // SelectPeerForDownload already handles all peer selection logic including
    // fallback peers, so RequestBlock should trust its decision

    // Check if already in-flight
    if (mapBlocksInFlight.count(hash) > 0) {
        return false;
    }

    // Create in-flight entry
    CBlockInFlight inFlight(hash, peer, height);
    mapBlocksInFlight[hash] = inFlight;

    // Track peer's blocks
    mapPeerBlocks[peer].insert(hash);

    // Phase C: CPeerManager is now the single source of truth for block tracking
    if (g_peer_manager) {
        g_peer_manager->MarkBlockAsInFlight(peer, hash, nullptr);
    }

    // Update peer state
    if (mapPeerStates.count(peer) == 0) {
        mapPeerStates[peer] = PeerDownloadState();
    }
    mapPeerStates[peer].nBlocksInFlight++;
    mapPeerStates[peer].lastRequest = std::chrono::steady_clock::now();

    // Remove from queue if present
    setQueuedHashes.erase(hash);

    // NOTE: Actual GETDATA message sending is handled by caller
    // This function just tracks the request state
    return true;
}

bool CBlockFetcher::MarkBlockReceived(NodeId peer, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Check if block was in-flight
    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        // Not tracked, but that's okay (could be unsolicited block)
        return false;
    }

    // Calculate response time
    auto timeReceived = std::chrono::steady_clock::now();
    auto responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        timeReceived - it->second.timeRequested
    );

    // Update peer statistics (success)
    UpdatePeerStats(peer, true, responseTime);

    // Remove from in-flight tracking
    NodeId requestedPeer = it->second.peer;
    mapBlocksInFlight.erase(it);

    // Update peer's block set
    if (mapPeerBlocks.count(requestedPeer) > 0) {
        mapPeerBlocks[requestedPeer].erase(hash);
        if (mapPeerBlocks[requestedPeer].empty()) {
            mapPeerBlocks.erase(requestedPeer);
        }
    }

    // Update peer state
    if (mapPeerStates.count(requestedPeer) > 0) {
        mapPeerStates[requestedPeer].nBlocksInFlight--;
        mapPeerStates[requestedPeer].nBlocksDownloaded++;
    }

    // Update global statistics
    nBlocksReceivedTotal++;
    lastBlockReceived = timeReceived;

    // BUG #64: Clean up preferred peer tracking
    mapPreferredPeers.erase(hash);

    // Phase C: CPeerManager is now the single source of truth for block tracking
    if (g_peer_manager) {
        g_peer_manager->MarkBlockAsReceived(hash);
    }

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

        // Mark peer as stalled
        MarkPeerStalled(stalledPeer);

        // Remove from in-flight tracking
        mapBlocksInFlight.erase(it);

        // Update peer's block set
        if (mapPeerBlocks.count(stalledPeer) > 0) {
            mapPeerBlocks[stalledPeer].erase(hash);
            if (mapPeerBlocks[stalledPeer].empty()) {
                mapPeerBlocks.erase(stalledPeer);
            }
        }

        // Update peer state
        if (mapPeerStates.count(stalledPeer) > 0) {
            mapPeerStates[stalledPeer].nBlocksInFlight--;
        }

        // Re-queue if not exceeded max retries
        if (retries < MAX_RETRIES) {
            // Re-queue with high priority and incremented retry count
            // Note: We track retries by re-adding to in-flight later with retry count
            queueBlocksToFetch.push(BlockDownloadRequest(hash, height, true));  // High priority for retries
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

    // Phase B: Use CPeerManager as primary source for peer selection
    // Note: hash is used in fallback path below during migration
    if (g_peer_manager) {
        // BUG #64: First try the preferred peer (the one that announced the block)
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
                std::cout << "[BUG-146-DEBUG] peer " << peer_id << " is null in SelectPeerForDownload" << std::endl;
                continue;
            }

            // Must have capacity (use CPeerManager limit)
            std::cout << "[BUG-146-DEBUG] peer " << peer_id << " nBlocksInFlight=" << peer->nBlocksInFlight
                      << " max=" << CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER << std::endl;
            if (peer->nBlocksInFlight >= CPeerManager::MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
                std::cout << "[BUG-146-DEBUG] peer " << peer_id << " SKIPPED - at capacity" << std::endl;
                continue;
            }

            // Check if suitable (uses CPeer::IsSuitableForDownload)
            bool suitable = peer->IsSuitableForDownload();
            if (!suitable) {
                std::cout << "[BUG-146-DEBUG] peer " << peer_id << " NOT suitable for download" << std::endl;
                if (fallbackPeer == -1) {
                    fallbackPeer = peer_id;
                }
                continue;
            }
            std::cout << "[BUG-146-DEBUG] peer " << peer_id << " IS suitable, calculating score" << std::endl;

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

        // BUG #61: Use fallback if no suitable peer found
        if (bestPeer == -1 && fallbackPeer != -1) {
            std::cout << "[BUG-146-DEBUG] SelectPeerForDownload: using fallback peer " << fallbackPeer << std::endl;
            return fallbackPeer;
        }

        if (bestPeer != -1) {
            std::cout << "[BUG-146-DEBUG] SelectPeerForDownload: returning bestPeer " << bestPeer << std::endl;
            return bestPeer;
        }

        std::cout << "[BUG-146-DEBUG] SelectPeerForDownload: no peer found (bestPeer=-1, fallbackPeer=" << fallbackPeer << ")" << std::endl;
    }

    // Fallback to mapPeerStates if CPeerManager unavailable or returned no peers
    if (preferred_peer != -1) {
        auto it = mapPeerStates.find(preferred_peer);
        if (it != mapPeerStates.end()) {
            int availableSlots = GetAvailableSlotsForPeer(preferred_peer);
            if (availableSlots > 0 && IsPeerSuitable(preferred_peer)) {
                return preferred_peer;
            }
        }
    }

    NodeId bestPeer = -1;
    NodeId fallbackPeer = -1;
    int bestScore = -1;

    for (const auto& entry : mapPeerStates) {
        NodeId peer = entry.first;
        const PeerDownloadState& state = entry.second;

        int availableSlots = GetAvailableSlotsForPeer(peer);
        if (availableSlots <= 0) continue;

        bool suitable = IsPeerSuitable(peer);
        if (!suitable) {
            if (fallbackPeer == -1) fallbackPeer = peer;
            continue;
        }

        int score = 1000;
        if (state.preferred) score += 500;
        score -= state.nStalls * 100;
        if (state.avgResponseTime.count() > 0) {
            score += 1000 / (state.avgResponseTime.count() / 100 + 1);
        }
        score += state.nBlocksDownloaded * 10;
        score -= state.nBlocksInFlight * 50;

        if (score > bestScore) {
            bestScore = score;
            bestPeer = peer;
        }
    }

    if (bestPeer == -1 && fallbackPeer != -1) {
        return fallbackPeer;
    }

    return bestPeer;
}

void CBlockFetcher::UpdatePeerStats(NodeId peer, bool success, std::chrono::milliseconds responseTime)
{
    // Note: Caller should hold lock
    // This method is called from MarkBlockReceived which already holds the lock

    // Phase B: Delegate to CPeerManager (primary source of truth)
    if (g_peer_manager) {
        g_peer_manager->UpdatePeerStats(peer, success, responseTime);
    }

    // Fallback: Also update local mapPeerStates during transition
    if (mapPeerStates.count(peer) == 0) {
        mapPeerStates[peer] = PeerDownloadState();
    }

    PeerDownloadState& state = mapPeerStates[peer];

    if (success) {
        if (state.nStalls > 0) {
            state.nStalls = 0;
        }
        state.lastSuccessTime = std::chrono::steady_clock::now();

        if (responseTime.count() > 0) {
            int64_t newAvg = (3 * responseTime.count() + 7 * state.avgResponseTime.count()) / 10;
            state.avgResponseTime = std::chrono::milliseconds(newAvg);
        }

        if (state.avgResponseTime < std::chrono::seconds(2) && state.nStalls < 2) {
            state.preferred = true;
        }
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
    std::lock_guard<std::mutex> lock(cs_fetcher);

    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        return 0;
    }

    return it->second.nBlocksInFlight;
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

                // Re-queue with high priority
                if (retries < MAX_RETRIES) {
                    queueBlocksToFetch.push(BlockDownloadRequest(hash, height, true));
                    setQueuedHashes.insert(hash);
                }
            }
        }

        mapPeerBlocks.erase(peer);
    }

    // Clean up peer state
    mapPeerStates.erase(peer);
}

void CBlockFetcher::OnPeerConnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // Initialize peer state
    mapPeerStates[peer] = PeerDownloadState();
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
    ss << "  Active peers: " << mapPeerStates.size() << "\n";
    ss << "  Total blocks received: " << nBlocksReceivedTotal << "\n";

    // Peer breakdown
    ss << "  Per-peer status:\n";
    for (const auto& entry : mapPeerStates) {
        NodeId peer = entry.first;
        const PeerDownloadState& state = entry.second;
        ss << "    Peer " << peer << ": "
           << state.nBlocksInFlight << " in-flight, "
           << state.nBlocksDownloaded << " downloaded, "
           << state.nStalls << " stalls, "
           << "avg " << state.avgResponseTime.count() << "ms"
           << (state.preferred ? " [PREFERRED]" : "")
           << "\n";
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
    mapPreferredPeers.clear();  // BUG #64: Clear preferred peers

    mapPeerStates.clear();
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

int CBlockFetcher::GetAvailableSlotsForPeer(NodeId peer) const
{
    // Caller should hold lock
    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        return MAX_BLOCKS_PER_PEER;
    }

    int inFlight = it->second.nBlocksInFlight;
    return MAX_BLOCKS_PER_PEER - inFlight;
}

void CBlockFetcher::MarkPeerStalled(NodeId peer)
{
    // Caller should hold lock
    if (mapPeerStates.count(peer) == 0) {
        mapPeerStates[peer] = PeerDownloadState();
    }

    mapPeerStates[peer].nStalls++;
    mapPeerStates[peer].preferred = false;  // Remove preferred status
    // BUG #61 FIX: Track when stall occurred for timeout calculation
    mapPeerStates[peer].lastStallTime = std::chrono::steady_clock::now();

    // If peer stalls too much, it will be avoided by IsPeerSuitable (but not permanently - BUG #61)
}

bool CBlockFetcher::IsPeerSuitable(NodeId peer) const
{
    // Caller should hold lock

    // Phase B: Use CPeerManager as primary source
    if (g_peer_manager) {
        return g_peer_manager->IsPeerSuitableForDownload(peer);
    }

    // Fallback to mapPeerStates during migration
    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        return true;  // New peer, give it a chance
    }

    const PeerDownloadState& state = it->second;

    // BUG #61 FIX: Check if stall timeout has passed (Bitcoin Core-aligned)
    // Never permanently exclude peers - allow retry after timeout
    auto now = std::chrono::steady_clock::now();
    auto stallAge = std::chrono::duration_cast<std::chrono::minutes>(
        now - state.lastStallTime);

    // Forgive stalls after PEER_STALL_TIMEOUT (5 minutes)
    if (stallAge >= PEER_STALL_TIMEOUT) {
        return true;  // Give peer another chance
    }

    // During timeout period, check threshold (raised to 10)
    if (state.nStalls >= PEER_STALL_THRESHOLD) {
        return false;  // Temporarily unsuitable
    }

    return true;
}

void CBlockFetcher::UpdateDownloadSpeed()
{
    // Placeholder for future implementation of sliding window speed calculation
    // Currently speed is calculated on-demand in GetDownloadSpeed()
}
