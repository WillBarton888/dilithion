// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/block_fetcher.h>
#include <net/node_state.h>  // BUG #69: Bitcoin Core-style per-peer block tracking
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

    std::cout << "[BlockFetcher] Queued block for download: height=" << height
              << " hash=" << hash.GetHex().substr(0, 16) << "..."
              << (announcing_peer != -1 ? " from peer " + std::to_string(announcing_peer) : "")
              << (highPriority ? " [HIGH PRIORITY]" : "") << std::endl;
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
        std::cout << "[BlockFetcher] Peer " << peer << " at capacity, cannot request block" << std::endl;
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

    // BUG #69: Also track in CNodeStateManager for bidirectional tracking
    // This provides single source of truth for in-flight blocks across the codebase
    CNodeStateManager::Get().MarkBlockAsInFlight(peer, hash, nullptr);

    // Update peer state
    if (mapPeerStates.count(peer) == 0) {
        mapPeerStates[peer] = PeerDownloadState();
    }
    mapPeerStates[peer].nBlocksInFlight++;
    mapPeerStates[peer].lastRequest = std::chrono::steady_clock::now();

    // Remove from queue if present
    setQueuedHashes.erase(hash);

    std::cout << "[BlockFetcher] Requested block from peer " << peer
              << ": height=" << height
              << " hash=" << hash.GetHex().substr(0, 16) << "..."
              << " (in-flight: " << mapBlocksInFlight.size() << "/" << MAX_BLOCKS_IN_FLIGHT << ")"
              << std::endl;

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

    // BUG #69: Also mark received in CNodeStateManager
    CNodeStateManager::Get().MarkBlockAsReceived(hash);

    std::cout << "[BlockFetcher] Block received from peer " << peer
              << " (response time: " << responseTime.count() << "ms)"
              << " in-flight remaining: " << mapBlocksInFlight.size()
              << std::endl;

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

    if (!result.empty()) {
        std::cout << "[BlockFetcher] Selected " << result.size() << " blocks for download "
                  << "(queue size: " << queueBlocksToFetch.size() << ")" << std::endl;
    }

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

    if (!timedOut.empty()) {
        std::cout << "[BlockFetcher] Found " << timedOut.size() << " timed-out block requests" << std::endl;
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

        std::cout << "[BlockFetcher] Block request timed out: peer=" << stalledPeer
                  << " height=" << height
                  << " hash=" << hash.GetHex().substr(0, 16) << "..."
                  << " retries=" << retries << std::endl;

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
            std::cout << "[BlockFetcher] Re-queued timed-out block for retry" << std::endl;
        } else {
            std::cerr << "[BlockFetcher] Block exceeded max retries, dropping: "
                      << hash.GetHex().substr(0, 16) << "..." << std::endl;
        }
    }
}

NodeId CBlockFetcher::SelectPeerForDownload(const uint256& hash, NodeId preferred_peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    // BUG #64: First try the preferred peer (the one that announced the block)
    if (preferred_peer != -1) {
        auto it = mapPeerStates.find(preferred_peer);
        if (it != mapPeerStates.end()) {
            int availableSlots = GetAvailableSlotsForPeer(preferred_peer);
            if (availableSlots > 0 && IsPeerSuitable(preferred_peer)) {
                std::cout << "[BlockFetcher] BUG #64: Using preferred peer " << preferred_peer
                          << " that announced this block" << std::endl;
                return preferred_peer;
            }
        }
    }

    // Find best peer based on:
    // 1. Has available capacity
    // 2. Low stall count
    // 3. Fast response time
    // 4. Preferred status

    NodeId bestPeer = -1;
    NodeId fallbackPeer = -1;  // BUG #61: Track stalled peer as fallback
    int bestScore = -1;

    for (const auto& entry : mapPeerStates) {
        NodeId peer = entry.first;
        const PeerDownloadState& state = entry.second;

        // Must have capacity
        int availableSlots = GetAvailableSlotsForPeer(peer);
        if (availableSlots <= 0) {
            continue;
        }

        // Check if suitable (not stalled too often)
        bool suitable = IsPeerSuitable(peer);
        if (!suitable) {
            // BUG #61: Track as fallback even if stalled
            if (fallbackPeer == -1) {
                fallbackPeer = peer;
            }
            continue;
        }

        // Calculate score (higher is better)
        int score = 1000;

        // Preferred peers get bonus
        if (state.preferred) {
            score += 500;
        }

        // Penalize for stalls
        score -= state.nStalls * 100;

        // Bonus for fast response time (inverse of time in ms)
        if (state.avgResponseTime.count() > 0) {
            score += 1000 / (state.avgResponseTime.count() / 100 + 1);  // Avoid division by zero
        }

        // Bonus for successful downloads
        score += state.nBlocksDownloaded * 10;

        // Penalize if already has many blocks in-flight (spread load)
        score -= state.nBlocksInFlight * 50;

        if (score > bestScore) {
            bestScore = score;
            bestPeer = peer;
        }
    }

    // BUG #61: Use fallback if no suitable peer found (prevents sync deadlock)
    if (bestPeer == -1 && fallbackPeer != -1) {
        std::cout << "[BlockFetcher] BUG #61: Using fallback peer " << fallbackPeer
                  << " (all peers marked as stalled - giving another chance)" << std::endl;
        return fallbackPeer;
    }

    if (bestPeer != -1) {
        std::cout << "[BlockFetcher] Selected peer " << bestPeer
                  << " for download (score: " << bestScore << ")" << std::endl;
    }

    return bestPeer;
}

void CBlockFetcher::UpdatePeerStats(NodeId peer, bool success, std::chrono::milliseconds responseTime)
{
    // Note: Caller should hold lock
    // This method is called from MarkBlockReceived which already holds the lock

    if (mapPeerStates.count(peer) == 0) {
        mapPeerStates[peer] = PeerDownloadState();
    }

    PeerDownloadState& state = mapPeerStates[peer];

    if (success) {
        // BUG #61 FIX: Reset stall count on successful block download (Bitcoin Core approach)
        // This prevents permanent peer exclusion and allows recovery
        if (state.nStalls > 0) {
            std::cout << "[BlockFetcher] BUG #61: Resetting stall count for peer " << peer
                      << " (was " << state.nStalls << ") after successful download" << std::endl;
            state.nStalls = 0;
        }
        state.lastSuccessTime = std::chrono::steady_clock::now();

        // Update average response time (exponential moving average)
        if (responseTime.count() > 0) {
            // EMA: new_avg = alpha * new_value + (1 - alpha) * old_avg
            // Using alpha = 0.3 for responsiveness
            int64_t newAvg = (3 * responseTime.count() + 7 * state.avgResponseTime.count()) / 10;
            state.avgResponseTime = std::chrono::milliseconds(newAvg);
        }

        // Mark as preferred if consistently fast (< 2 seconds avg) and reliable (< 2 stalls)
        if (state.avgResponseTime < std::chrono::seconds(2) && state.nStalls < 2) {
            state.preferred = true;
        }
    } else {
        // Failure - already handled by MarkPeerStalled
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

    std::cout << "[BlockFetcher] Removed block from queue: "
              << hash.GetHex().substr(0, 16) << "..." << std::endl;
}

void CBlockFetcher::OnPeerDisconnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_fetcher);

    std::cout << "[BlockFetcher] Peer " << peer << " disconnected, re-queuing in-flight blocks" << std::endl;

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

    std::cout << "[BlockFetcher] Peer " << peer << " connected, initializing download state" << std::endl;

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

    std::cout << "[BlockFetcher] All state cleared" << std::endl;
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

    std::cout << "[BlockFetcher] Peer " << peer << " stalled "
              << "(total stalls: " << mapPeerStates[peer].nStalls << ")" << std::endl;

    // If peer stalls too much, it will be avoided by IsPeerSuitable (but not permanently - BUG #61)
}

bool CBlockFetcher::IsPeerSuitable(NodeId peer) const
{
    // Caller should hold lock
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
